/*
 * This file is part of MultiROM.
 *
 * MultiROM is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * MultiROM is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with MultiROM.  If not, see <http://www.gnu.org/licenses/>.
 */

extern "C" {
#define _GNU_SOURCE
#include <sys/stat.h>
#include <sys/mount.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <stdio.h>
#include <mntent.h>
#include <stdlib.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/klog.h>
#include <cutils/android_reboot.h>
#include <pthread.h>
#include <selinux/selinux.h>

#include "devices.h"
#include "../lib/log.h"
#include "../lib/util.h"
#include "../lib/fstab.h"
#include "../lib/inject.h"
#include "../version.h"
#include "adb.h"
#include "../hooks.h"
#include "encryption.h"
#include "../no_kexec.h"

#ifdef MR_POPULATE_BY_NAME_PATH
	#include "Populate_ByName_using_emmc.c"
#endif

#include "trampoline.h"
}

#include <iostream>
#include <string>
#include <vector>

static char path_multirom[64] = { 0 };

int fork_and_exec_with_stdout(char *cmd, char *const *envp)
{
   int fd[2];
   int exit_code = -1;
   char* command[] = {cmd, NULL};
   if(pipe2(fd, O_CLOEXEC) < 0)
        return -1;

    pid_t pid = fork();
    if (pid < 0)
    {
        close(fd[0]);
        close(fd[1]);
        return pid;
    }

    if(pid == 0) // child
    {
        close(fd[0]);
        dup2(fd[1], 1);  // send stdout to the pipe
        dup2(fd[1], 2);  // send stderr to the pipe
        close(fd[1]);

        if (execve(command[0], command, envp) == -1) {
            ERROR("execve failed %s\n", strerror(errno));
        }
        _exit(127);
    }
    else
    {
        close(fd[1]);

        char *res = (char*)malloc(512);
        char buffer[512];
        int size = 512, written = 0, len;
        while ((len = read(fd[0], buffer, sizeof(buffer))) > 0)
        {
            if(written + len + 1 > size)
            {
                size = written + len + 256;
                res = (char*)realloc(res, size);
            }
            memcpy(res+written, buffer, len);
            written += len;
        }
        res[written] = 0;

        close(fd[0]);

        waitpid(pid, &exit_code, 0);
        ERROR("%s\n", res);

        if(written == 0)
        {
            free(res);
            return pid;
        }
        return pid;
    }
    return pid;
}

static int fork_and_exec_with_strace(char *cmd, char** env)
{
    pid_t pID = fork();
    if(pID == 0)
    {
        char* args[] = {"/mrom_enc/strace", "-o", NULL, "-f", NULL, NULL};
        char strace_arg1[100];
        sprintf(strace_arg1, "strace-%s", (cmd + 10));
        args[2] = strace_arg1;
        args[4] = cmd;
        INFO("running %s %s %s %s %s\n", args[0], args[1], args[2], args[3], args[4]);
        stdio_to_null();
        setpgid(0, getpid());
        execve(args[0], args, env);
        ERROR("Failed to exec %s: %s\n", args[0], strerror(errno));
        _exit(127);
    }
    return pID;
}

static int find_multirom(void)
{
    int i;
    struct stat info;

    static const char *paths[] = {
        REALDATA"/media/0/MultiROM/multirom",
        REALDATA"/media/MultiROM/multirom",
        REALDATA"/media/0/multirom", // 4.2
        REALDATA"/media/multirom",
        NULL,
    };

    for(i = 0; paths[i]; ++i) {
        if(stat(paths[i], &info) < 0)
            continue;

        strcpy(path_multirom, paths[i]);

        if (i < 2) {
            // Make sure to set the container dir to immutable
            char main_path[64];
            strncpy(main_path, path_multirom, strlen(path_multirom) - (sizeof("/multirom") - 1));
            main_path[strlen(path_multirom) - (sizeof("/multirom") - 1)] = '\0';

            int fd = open(main_path, O_RDONLY | O_NONBLOCK);
            if (fd >= 0) {
                long flags;
                if (ioctl(fd, FS_IOC_GETFLAGS, &flags) >= 0) {
                    flags |= FS_IMMUTABLE_FL;
                    if (ioctl(fd, FS_IOC_SETFLAGS, &flags) < 0)
                        ERROR("Failed FS_IOC_SETFLAGS: %s!\n", strerror(errno));
                    else
                        INFO("Set FS_IMMUTABLE_FL on %s.\n", main_path);
                }
                else
                    ERROR("Failed FS_IOC_GETFLAGS: %s!\n", strerror(errno));
                close(fd);
            }
            else
                ERROR("Failed to open %s: %s!\n", main_path, strerror(errno));
        }
        return 0;
    }
    return -1;
}

static void run_multirom(int isFbe)
{
    char path[256];
    struct stat info;

    // busybox
    sprintf(path, "%s/%s", path_multirom, BUSYBOX_BIN);
    if (stat(path, &info) < 0)
    {
        ERROR("Could not find busybox: %s\n", path);
        return;
    }
    chmod(path, EXEC_MASK);

    // restart after crash
    sprintf(path, "%s/restart_after_crash", path_multirom);
    int restart = (stat(path, &info) >= 0);

    // multirom
    sprintf(path, "%s/%s", path_multirom, MULTIROM_BIN);
    if (stat(path, &info) < 0)
    {
        ERROR("Could not find multirom: %s\n", path);
        return;
    }
    chmod(path, EXEC_MASK);

    const char *cmd[] = { path, isFbe ? "alwaysreboot" : NULL, NULL };
    do
    {
        ERROR("Running multirom\n");
        int res = run_cmd((char**)cmd);
        if(res == 0)
            break;
        else
            ERROR("MultiROM exited with status code %d!\n", res);
    }
    while(restart);
}

static int try_mount_all_entries(struct fstab *fstab, struct fstab_part *first_data_p)
{
    size_t i;
    struct fstab_part *p_itr = first_data_p;

    do
    {
        // Remove nosuid flag, because secondary ROMs have
        // su binaries on /data
        p_itr->mountflags &= ~(MS_NOSUID);

        if(mount(p_itr->device, REALDATA, p_itr->type, p_itr->mountflags, p_itr->options) >= 0) {
            struct stat info;
            if(stat("/realdata/unencrypted/key/version", &info) < 0) {
                return 0;
            } else {
                if (!mrom_is_second_boot() && stat("/realdata/media/MultiROM/multirom", &info) >= 0) {
                    INFO("Multirom found");
                    return 0;
                } else {
                    INFO("File system is FBE encrypted");
                    return -2;
                }
            }
        }
    }
    while((p_itr = fstab_find_next_by_path(fstab, "/data", p_itr)));

    ERROR("Failed to mount /realdata with data from fstab, trying all filesystems\n");

    const char *fs_types[] = { "ext4", "f2fs", "ext3", "ext2" };
    const char *fs_opts [] = {
        "barrier=1,data=ordered,nomblk_io_submit,noauto_da_alloc,errors=panic", // ext4
        "inline_xattr,flush_merge", // f2fs
        "", // ext3
        "" // ext2
    };

    for(i = 0; i < ARRAY_SIZE(fs_types); ++i)
    {
        if(mount(first_data_p->device, REALDATA, fs_types[i], first_data_p->mountflags, fs_opts[i]) >= 0)
        {
            INFO("/realdata successfuly mounted with fs %s\n", fs_types[i]);
            struct stat info;
            if(stat("/realdata/unencrypted/key/version", &info) < 0) {
                return 0;
            } else {
                if (!mrom_is_second_boot() && stat("/realdata/media/MultiROM/multirom", &info) >= 0) {
                    INFO("Multirom found");
                    return 0;
                } else {
                    INFO("File system is FBE encrypted\n");
                    return -2;
                }
            }
            return 0;
        }
    }

    return -1;
}

static int mount_and_run(struct fstab *fstab)
{
    struct fstab_part *datap = fstab_find_first_by_path(fstab, "/data");
    if(!datap)
    {
        ERROR("Failed to find /data partition in fstab\n");
        return -1;
    }

    if(access(datap->device, R_OK) < 0)
    {
        INFO("Waiting for %s because error %s\n", datap->device, strerror(errno));
        if(wait_for_file(datap->device, 5) < 0)
        {
            ERROR("Waiting too long for dev %s\n", datap->device);
            return -1;
        }
    }

    mkdir(REALDATA, 0755);
    mkdir("/data", 0755);

    int ret = try_mount_all_entries(fstab, datap);
    if(ret < 0)
    {
#ifndef MR_ENCRYPTION
        ERROR("Failed to mount /data with all possible filesystems!\n");
        return -1;
#else
        INFO("Failed to mount /realdata, trying encryption...\n");
        switch(encryption_before_mount(fstab, ret == -2))
        {
            case ENC_RES_ERR:
                ERROR("/data decryption failed!\n");
                return -1;
            case ENC_RES_BOOT_INTERNAL:
                return 0;
            case ENC_RES_BOOT_RECOVERY:
                sync();
                do_reboot(REBOOT_RECOVERY); // REBOOT_RECOVERY
                while (1)
                    sleep(1);
                // we're never returning
                return 0;
            default:
            case ENC_RES_OK:
            {
                if(ret != -2 && try_mount_all_entries(fstab, datap) < 0)
                {
                    ERROR("Failed to mount decrypted /data with all possible filesystems!\n");
                    return -1;
                }
                break;
            }
        }
#endif
    }

    if (ret == -2 && !nokexec_is_skip_mr() || ret != -2) {
        INFO("skip mr flag false.. running multirom");
        if(find_multirom() == -1)
        {
            ERROR("Could not find multirom folder!\n");
            return -1;
        }

        adb_init(path_multirom);
        run_multirom(ret == -2);
        adb_quit();
    }
    return 0;
}

static int is_charger_mode(void)
{
    char buff[2048] = { 0 };
    int charger_mode = 0;

    FILE *f = fopen("/proc/cmdline", "re");
    if(!f)
        return 0;

    while (fgets(buff, sizeof(buff), f) != NULL)
    {
        if (strstr(buff, "androidboot.mode=charger") != NULL)
        {
            charger_mode = 1;
            break;
        }
    }

    fclose(f);

    return charger_mode;
}

static void fixup_symlinks(void)
{
    static const char *init_links[] = { "/sbin/ueventd", "/sbin/watchdogd" };

    size_t i;
    ssize_t len;
    char buff[64];
    struct stat info;

    for(i = 0; i < ARRAY_SIZE(init_links); ++i)
    {
        if(lstat(init_links[i], &info) < 0 || !S_ISLNK(info.st_mode))
            continue;

        if (info.st_size < sizeof(buff)-1)
        {
            len = readlink(init_links[i], buff, sizeof(buff)-1);
            if(len >= 0)
            {
                buff[len] = 0;
                // if the symlink already points to ../init, skip it.
                if(strcmp(buff, "../init") == 0)
                    continue;
            }
        }

        ERROR("Fixing up symlink '%s' -> '%s' to '%s' -> '../init')\n", init_links[i], buff, init_links[i]);
        unlink(init_links[i]);
        symlink("../init", init_links[i]);
    }
}

static void switch_root(const char* path) {
    INFO("Switch root to %s\n", path);
    FILE *fp =  setmntent("/proc/mounts", "re");
    if (fp) {
        struct mntent mentry;
        char buf[4096];
        std::vector<std::string> v;
        bool add = true;
        while (getmntent_r(fp, &mentry, buf, sizeof(buf))) {
            if (!strcmp(mentry.mnt_dir, "/") || !strcmp(mentry.mnt_dir, path)) {
                INFO("skip %s\n", mentry.mnt_dir);
                continue;
            }

            for (auto i : v) {
                if (!strcmp(mentry.mnt_dir, i.data())) {
                    INFO("%s %s %d not adding to vector\n", mentry.mnt_dir, i.data(), i.length());
                    add = false;
                    break;
                } else {
                    add = true;
                }
            }

            if (add) {
                v.emplace_back(mentry.mnt_dir);
                INFO("%s added to vector\n", mentry.mnt_dir);
            } else {
                INFO("%s not added to vector\n", mentry.mnt_dir);
            }
        }
        endmntent(fp);

            for (auto i : v) {
                char* new_path = NULL;
                asprintf(&new_path, "%s%s", path, i.data());
                INFO("move mount point %s to %s\n", i.data(), new_path);
                mkdir(new_path, 0755);
                mount(i.data(), new_path, NULL, MS_MOVE, NULL);
            }
    }
}

static int do_cmdline(int argc, char *argv[])
{
    int i;
    char *inject_path = NULL;
    char *mrom_dir = NULL;
    int force_inject = 0;

    if (argc > 1 && !strcmp(argv[1], "selinux_setup")) {
        INFO("multirom second stage init\n");
        //remove_dir("/system");
        switch_root("/system_root");
		int error = chdir("/system_root");
        if (error == -1) {
            INFO("chdir failed!!: %s\n", strerror(errno));
        } else {
            INFO("chdir returned %d\n", error);
        }
        error = mount("/system_root", "/", NULL, MS_MOVE, NULL);
        if (error == -1) {
            INFO("mount failed!!: %s\n", strerror(errno));
        } else {
            INFO("mount returned %d\n", error);
        }
        error = chroot(".");
        if (error == -1) {
            INFO("chroot failed!!: %s\n", strerror(errno));
        } else {
            INFO("chroot returned %d\n", error);
        }
        struct stat info;
        if(stat("/system/etc/selinux", &info) < 0) {
            INFO("/system/etc/selinux does not exist!\n");
        } else {
            INFO("/system/etc/selinux exists\n");
        }
        if (stat("/vendor/etc/selinux", &info) < 0) {
            INFO("/vendor/etc/selinux does not exist!\n");
        } else {
            INFO("/vendor/etc/selinux exists\n");
        }
        int res;
        static char *const cmd[] = { "/init", "selinux_setup", NULL };
        res = execv(cmd[0], cmd);
        return 0;
	}


    for(i = 1; i < argc; ++i)
    {
        if(strcmp(argv[i], "-v") == 0)
        {
            printf("%d\n", VERSION_TRAMPOLINE);
            fflush(stdout);
            return 0;
        }
        else if(strstartswith(argv[i], "--inject="))
            inject_path = argv[i] + strlen("--inject=");
        else if(strstartswith(argv[i], "--mrom_dir="))
            mrom_dir = argv[i] + strlen("--mrom_dir=");
        else if(strcmp(argv[i], "-f") == 0)
            force_inject = 1;
    }

    if(inject_path)
    {
        if(!mrom_dir)
        {
            printf("--mrom_dir=[path to multirom's data dir] needs to be specified!\n");
            fflush(stdout);
            return 1;
        }

        mrom_set_dir(mrom_dir);
        mrom_set_log_tag("trampoline_inject");
        return inject_bootimg(inject_path, force_inject);
    }

    printf("Usage: trampoline -v\n");
    printf("       trampoline --inject=<path to boot.img> --mrom_dir=<path to multirom's data dir> [-f]\n");
    return 1;
}

static int run_core(void)
{
    int res = -1;
    struct fstab *fstab = NULL;

#ifndef MR_DEVICE_HAS_DRM_GRAPHICS
    if(wait_for_file("/dev/graphics/fb0", 5) < 0)
    {
        ERROR("Waiting too long for fb0");
        goto exit;
    }
#endif

#ifdef MR_POPULATE_BY_NAME_PATH
    Populate_ByName_using_emmc();
#endif

    fstab = fstab_auto_load();
    if(!fstab)
        goto exit;

#if 0
    fstab_dump(fstab); //debug
#endif

    // mount and run multirom from sdcard
    res = mount_and_run(fstab);
    if(res < 0 && mrom_is_second_boot())
    {
        ERROR("This is second boot and we couldn't mount /data, reboot!\n");
        sync();
        //android_reboot(ANDROID_RB_RESTART, 0, 0);
        do_reboot(REBOOT_RECOVERY); // favour reboot to recovery, to avoid possible bootlooping
        while(1)
            sleep(1);
    }

    if(access(KEEP_REALDATA, F_OK) < 0) {
        umount(REALDATA);
        rmdir(REALDATA);
        encryption_destroy();
    }

    encryption_cleanup();

exit:
    if(fstab)
        fstab_destroy(fstab);

    return res;
}

char *trampoline_get_klog(void)
{
    int len = klogctl(10, NULL, 0);
    if      (len < 16*1024)      len = 16*1024;
    else if (len > 16*1024*1024) len = 16*1024*1024;

    char *buff = (char*)malloc(len + 1);
    len = klogctl(3, buff, len);
    if(len <= 0)
    {
        ERROR("Could not get klog!\n");
        free(buff);
        return NULL;
    }
    buff[len] = 0;
    return buff;
}

int trampoline_copy_log(char *klog, const char *dest_path_relative)
{
    int res = 0;
    int freeLog = (klog == NULL);

    if(!klog)
        klog = trampoline_get_klog();

    if(klog)
    {
        char path[256];
        snprintf(path, sizeof(path), "%s", dest_path_relative);
        FILE *f = fopen(path, "we");

        if(f)
        {
            fwrite(klog, 1, strlen(klog), f);
            fclose(f);
            chmod(path, 0777);
        }
        else
        {
            ERROR("Failed to open %s!\n", path);
            res = -1;
        }
    }
    else
    {
        ERROR("Could not get klog!\n");
        res = -1;
    }

    if(freeLog)
        free(klog);
    return res;
}

void klog_periodic(void* ptr) {
    while(1) {
        usleep(2000000);
        trampoline_copy_log(NULL, "/data/last_kmsg");
    }
}

int main(int argc, char *argv[])
{
    if (argc > 1)
        return do_cmdline(argc, argv);

    int res;
    static char *const cmd[] = { "/init", NULL };

    umask(000);

    // Init only the little we need, leave the rest for real init
    mkdir("/dev", 0755);
    mkdir("/dev/pts", 0755);
    mkdir("/dev/socket", 0755);
    mkdir("/proc", 0755);
    mkdir("/sys", 0755);
    mkdir("/tmp", 0755);

    mount("tmpfs", "/dev", "tmpfs", MS_NOSUID, "mode=0755");
    mount("devpts", "/dev/pts", "devpts", 0, NULL);
    mount("proc", "/proc", "proc", 0, NULL);
    mount("sysfs", "/sys", "sysfs", 0, NULL);
    mount("pstore", "/sys/fs/pstore", "pstore", 0, NULL);
    mount("selinuxfs", "/sys/fs/selinux", "selinuxfs", 0, NULL);

#if MR_USE_DEBUGFS_MOUNT
    // Mount the debugfs kernel sysfs
    mkdir("/sys/kernel/debug", 0755);
    mount("debugfs", "/sys/kernel/debug", "debugfs", 0, NULL);
#endif

    // output all messages to dmesg,
    // but it is possible to filter out INFO messages
    klog_set_level(6);

    mrom_set_log_tag("trampoline");
    INFO("Running trampoline v%d\n", VERSION_TRAMPOLINE);

    if(is_charger_mode())
    {
        INFO("Charger mode detected, skipping multirom\n");
        goto run_main_init;
    }

#if MR_DEVICE_HOOKS >= 3
    tramp_hook_before_device_init();
#endif

    INFO("Initializing devices...\n");
    devices_init();
    INFO("Done initializing\n");

    if (nokexec_is_skip_mr()) {
        INFO("skip mr flag true.. setting it to false for next boot\n");
        nokexec_unset_skip_mr_flag();
    } else {
        run_core();
    }

    // close and destroy everything
    devices_close();

run_main_init:
    umount("/dev/pts");
    rmdir("/dev/pts");
    rmdir("/dev/socket");
    rmdir("/tmp");

    if(access(KEEP_REALDATA, F_OK) < 0) {
        umount("/dev");
    }

#if MR_USE_DEBUGFS_MOUNT
    umount("/sys/kernel/debug");
#endif

    if (access("/fakefsbat/", F_OK)) {
        DIR* dir = opendir("/proc/device-tree/firmware/android");
        copy_dir_contents(dir, "/proc/device-tree/firmware/android", "/fakefsbat", NULL);
        //remove("/fakefstab/fstab/system/mnt_point");
        closedir(dir);
        //remove("/fakefstab/fstab/vendor/mnt_point");
    }
    umount("/proc");
    umount("/sys/fs/pstore");
    umount("/sys/fs/selinux");
    if(umount("/sys")) {
        ERROR("sysfs unmount failed :%s\n", strerror(errno));
    }

    INFO("Running main_init\n");

    fixup_symlinks();

    //INFO("%s\n", read_file("strace-qseecomd"));

    char* context = (char*)calloc(1, 50);
    getfilecon("/main_init", &context);
    INFO("context of main_init is %s", context);
    chmod("/main_init", EXEC_MASK);
    rename("/main_init", "/init");
    getfilecon("/init", &context);
    INFO("context of init is %s", context);

    //setexeccon("u:object_r:kernel:s0");

    //trampoline_copy_log(NULL, "/data/last_kmsg");
    res = execve(cmd[0], cmd, NULL);
    //trampoline_copy_log(NULL, "/data/last_kmsg");
    ERROR("execve returned %d %d %s\n", res, errno, strerror(errno));
    return 0;
}
