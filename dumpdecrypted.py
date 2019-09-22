 #  ______ ______ ______ ______ ______ ______ ______ ______ ______ ______ ______ ______ ______ ______ ______ ______ ______ 
 # |______|______|______|______|______|______|______|______|______|______|______|______|______|______|______|______|______| 
 #        _        ___  _      _      _____  ____   
 #       (_)      / _ \| |    | |    |  __ \|  _ \  
 #  __  ___  __ _| | | | |    | |    | |  | | |_) | 
 #  \ \/ / |/ _` | | | | |    | |    | |  | |  _ <  
 #   >  <| | (_| | |_| | |____| |____| |__| | |_) | 
 #  /_/\_\_|\__,_|\___/|______|______|_____/|____/                                                                                                                   
 #  ______ ______ ______ ______ ______ ______ ______ ______ ______ ______ ______ ______ ______ ______ ______ ______ ______ 
 # |______|______|______|______|______|______|______|______|______|______|______|______|______|______|______|______|______|

import lldb
import os
import shlex
import optparse
import json
import re

def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
    'command script add -f dumpdecrypted.handle_command dumpdecrypted -h "[usage] dumpdecrypted"')
    print('========')
    print('[dumpdecrypted]: the lldb dumpdecrypted version')
    print('\tdumpdecrypted')
    print('\tmore usage, try "dumpdecrypted -h"')
                    
def handle_command(debugger, command, exe_ctx, result, internal_dict):
    command_args = shlex.split(command, posix=False)
    parser = generate_option_parser()
    try:
        (options, args) = parser.parse_args(command_args)
    except:
        result.SetError(parser.usage)
        return
        
    target = exe_ctx.target
    thread = exe_ctx.thread
    
    ret = dumpdecrypted(debugger)
    result.AppendMessage(str(ret))
            
    return 

def getMainImagePath(debugger):
    
    command_script = r''' 
    const char *path = (char *)[[[NSBundle mainBundle] executablePath] UTF8String];
    path
    '''
    # is in executable path?
    ret = exeScript(debugger, command_script)
    ret = ret.strip()
    return ret[1:-1]

def getMainImageMachOHeader(debugger):
    command_script = r''' 
    typedef integer_t       cpu_type_t;
    typedef integer_t       cpu_subtype_t;
    typedef integer_t       cpu_threadtype_t;

    struct mach_header_64 {
        uint32_t    magic;      /* mach magic number identifier */
        cpu_type_t  cputype;    /* cpu specifier */
        cpu_subtype_t   cpusubtype; /* machine specifier */
        uint32_t    filetype;   /* type of file */
        uint32_t    ncmds;      /* number of load commands */
        uint32_t    sizeofcmds; /* the size of all the load commands */
        uint32_t    flags;      /* flags */
        uint32_t    reserved;   /* reserved */
    };
    struct mach_header_64* header = (struct mach_header_64*)_dyld_get_image_header(0);

    uint64_t header_int = (uint64_t)header;

    header_int
    '''
    # is in executable path?
    ret = exeScript(debugger, command_script)
    return hex(int(ret, 10))

def dumpdecrypted(debugger):
    command_script_header = r'''
    // header
    #define MH_MAGIC    0xfeedface  /* the mach magic number */
    #define MH_CIGAM    0xcefaedfe  /* NXSwapInt(MH_MAGIC) */

    #define MH_MAGIC_64 0xfeedfacf /* the 64-bit mach magic number */
    #define MH_CIGAM_64 0xcffaedfe /* NXSwapInt(MH_MAGIC_64) */

    #define LC_ENCRYPTION_INFO 0x21 /* encrypted segment information */
    #define LC_ENCRYPTION_INFO_64 0x2C /* 64-bit encrypted segment information */

    #define FAT_MAGIC   0xcafebabe
    #define FAT_CIGAM   0xbebafeca  /* NXSwapLong(FAT_MAGIC) */

    #define O_RDONLY        0x0000          /* open for reading only */
    #define O_WRONLY        0x0001          /* open for writing only */
    #define O_RDWR          0x0002          /* open for reading and writing */
    #define O_ACCMODE       0x0003          /* mask for above modes */

    #define SEEK_CUR    1   /* set file offset to current plus offset */
    #define SEEK_SET    0

    #define errno (*__error())

    typedef integer_t       cpu_type_t;
    typedef integer_t       cpu_subtype_t;
    typedef integer_t       cpu_threadtype_t;

    #define swap32(value) (((value & 0xFF000000) >> 24) | ((value & 0x00FF0000) >> 8) | ((value & 0x0000FF00) << 8) | ((value & 0x000000FF) << 24) )

    struct mach_header {
        uint32_t    magic;      /* mach magic number identifier */
        cpu_type_t  cputype;    /* cpu specifier */
        cpu_subtype_t   cpusubtype; /* machine specifier */
        uint32_t    filetype;   /* type of file */
        uint32_t    ncmds;      /* number of load commands */
        uint32_t    sizeofcmds; /* the size of all the load commands */
        uint32_t    flags;      /* flags */
    };

    struct mach_header_64 {
        uint32_t    magic;      /* mach magic number identifier */
        cpu_type_t  cputype;    /* cpu specifier */
        cpu_subtype_t   cpusubtype; /* machine specifier */
        uint32_t    filetype;   /* type of file */
        uint32_t    ncmds;      /* number of load commands */
        uint32_t    sizeofcmds; /* the size of all the load commands */
        uint32_t    flags;      /* flags */
        uint32_t    reserved;   /* reserved */
    };

    struct load_command {
        uint32_t cmd;       /* type of load command */
        uint32_t cmdsize;   /* total size of command in bytes */
    };

    struct encryption_info_command {
       uint32_t cmd;        /* LC_ENCRYPTION_INFO */
       uint32_t cmdsize;    /* sizeof(struct encryption_info_command) */
       uint32_t cryptoff;   /* file offset of encrypted range */
       uint32_t cryptsize;  /* file size of encrypted range */
       uint32_t cryptid;    /* which enryption system,0 means not-encrypted yet */
    };

    struct fat_header {
        uint32_t    magic;      /* FAT_MAGIC or FAT_MAGIC_64 */
        uint32_t    nfat_arch;  /* number of structs that follow */
    };

    struct fat_arch {
        cpu_type_t  cputype;    /* cpu specifier (int) */
        cpu_subtype_t   cpusubtype; /* machine specifier (int) */
        uint32_t    offset;     /* file offset to this object file */
        uint32_t    size;       /* size of this object file */
        uint32_t    align;      /* alignment as a power of 2 */
    };
    '''
    command_script_init = 'struct mach_header* mh = (struct mach_header*)_dyld_get_image_header(0);'
    command_script_init += 'const char *path = (char *)[[[NSBundle mainBundle] executablePath] UTF8String];'

    command_script = command_script_header + command_script_init

    command_script += r'''
    struct load_command *lc;
    struct encryption_info_command *eic;
    struct fat_header *fh;
    struct fat_arch *arch;
    char buffer[1024];
    char rpath[4096],npath[4096]; /* should be big enough for PATH_MAX */
    unsigned int fileoffs = 0, off_cryptid = 0, restsize;
    int i,fd,outfd,r,n,toread;
    char *tmp;
    
    if (realpath(path, rpath) == NULL) {
        strlcpy(rpath, path, sizeof(rpath));
    }
    /* extract basename */
    tmp = strrchr(rpath, '/');
    printf("\n\n");
    if (tmp == NULL) {
        printf("[-] Unexpected error with filename.\n");
        _exit(1);
    } else {
        printf("[+] Dumping %s\n", tmp+1);
    }

    /* detect if this is a arm64 binary */
    if (mh->magic == MH_MAGIC_64) {
        lc = (struct load_command *)((unsigned char *)mh + sizeof(struct mach_header_64));
        printf("[+] detected 64bit ARM binary in memory.\n");
    } else { /* we might want to check for other errors here, too */
        lc = (struct load_command *)((unsigned char *)mh + sizeof(struct mach_header));
        printf("[+] detected 32bit ARM binary in memory.\n");
    }
    /* searching all load commands for an LC_ENCRYPTION_INFO load command */

    for (i=0; i<mh->ncmds; i++) {
        if (lc->cmd == LC_ENCRYPTION_INFO || lc->cmd == LC_ENCRYPTION_INFO_64) {

            eic = (struct encryption_info_command *)lc;
            /* If this load command is present, but data is not crypted then exit */
            if (eic->cryptid == 0) {
                break;
            }

            off_cryptid=(off_t)((uint8_t*)&eic->cryptid - (uint8_t*)mh);
            
            printf("[+] offset to cryptid found: @%p(from %p) = %x\n", &eic->cryptid, mh, off_cryptid);
            
            printf("[+] Found encrypted data at address %08x of length %u bytes - type %u.\n", eic->cryptoff, eic->cryptsize, eic->cryptid);
            
            printf("[+] Opening %s for reading.\n", rpath);

            fd = open(rpath, O_RDONLY);
            if (fd == -1) {
                printf("[-] Failed opening.\n");
                break;
            }
            printf("[+] Reading header\n");
            n = read(fd, (void *)buffer, sizeof(buffer));
            if (n != sizeof(buffer)) {
                printf("[W] Warning read only %d bytes\n", n);
            }

            printf("[+] Detecting header type\n");
            fh = (struct fat_header *)buffer;

            /* Is this a FAT file - we assume the right endianess */
            if (fh->magic == FAT_CIGAM) {
                printf("[+] Executable is a FAT image - searching for right architecture\n");
                arch = (struct fat_arch *)&fh[1];
                for (i=0; i<swap32(fh->nfat_arch); i++) {
                    if ((mh->cputype == swap32(arch->cputype)) && (mh->cpusubtype == swap32(arch->cpusubtype))) {
                        fileoffs = swap32(arch->offset);
                        printf("[+] Correct arch is at offset %u in the file\n", fileoffs);
                        break;
                    }
                    arch++;
                }
                if (fileoffs == 0) {
                    printf("[-] Could not find correct arch in FAT image\n");
                    _exit(1);
                }
            } else if (fh->magic == MH_MAGIC || fh->magic == MH_MAGIC_64) {
                printf("[+] Executable is a plain MACH-O image\n");
            } else {
                printf("[-] Executable is of unknown type\n");
                break;
            }

            NSString *docPath = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES)[0];
            
            strlcpy(npath, docPath.UTF8String, sizeof(npath));
            strlcat(npath, tmp, sizeof(npath));
            strlcat(npath, ".decrypted", sizeof(npath));
            strlcpy(buffer, npath, sizeof(buffer));
            printf("[+] Opening %s for writing.\n", npath);

            outfd = open(npath, O_RDWR|O_CREAT|O_TRUNC, 0644);
            if (outfd == -1) {
                if (strncmp("/private/var/mobile/Applications/", rpath, 33) == 0) {
                    printf("[-] Failed opening. Most probably a sandbox issue. Trying something different.\n");
                    
                    /* create new name */
                    strlcpy(npath, "/private/var/mobile/Applications/", sizeof(npath));
                    tmp = strchr(rpath+33, '/');
                    if (tmp == NULL) {
                        printf("[-] Unexpected error with filename.\n");
                        return;
                    }
                    tmp++;
                    *tmp++ = 0;
                    strlcat(npath, rpath+33, sizeof(npath));
                    strlcat(npath, "tmp/", sizeof(npath));
                    strlcat(npath, buffer, sizeof(npath));
                    printf("[+] Opening %s for writing.\n", npath);
                    outfd = open(npath, O_RDWR|O_CREAT|O_TRUNC, 0644);
                }
                if (outfd == -1) {
                    printf("[-] Failed opening\n");
                    break;
                }
            }

            /* calculate address of beginning of crypted data */
            n = fileoffs + eic->cryptoff;
            
            restsize = lseek(fd, 0, SEEK_END) - n - eic->cryptsize;
            lseek(fd, 0, SEEK_SET);
            
            printf("[+] Copying the not encrypted start of the file\n");
            /* first copy all the data before the encrypted data */
            while (n > 0) {
                toread = (n > sizeof(buffer)) ? sizeof(buffer) : n;
                r = read(fd, buffer, toread);
                if (r != toread) {
                    printf("[-] Error reading file\n");
                    return;
                }
                n -= r;
                
                r = write(outfd, buffer, toread);
                if (r != toread) {
                    printf("[-] Error writing file\n");
                    return;
                }
            }

            /* now write the previously encrypted data */

            printf("[+] Dumping the decrypted data into the file\n");

            // (unsigned char *)mh + eic->cryptoff

            r = write(outfd, (unsigned char *)mh + eic->cryptoff, eic->cryptsize);
            if (r != eic->cryptsize) {
                uint64_t flag = (uint64_t)(mh);
                printf("Error no.%d: %s\n", errno, strerror(errno));
                printf("[-] Error writing file r=%lx offset=%lx size=%lx flag=%lx\n", r,eic->cryptoff, eic->cryptsize, flag);
                return;
            }
            
            /* and finish with the remainder of the file */
            n = restsize;
            lseek(fd, eic->cryptsize, SEEK_CUR);
            printf("[+] Copying the not encrypted remainder of the file\n");
            while (n > 0) {
                toread = (n > sizeof(buffer)) ? sizeof(buffer) : n;
                r = read(fd, buffer, toread);
                if (r != toread) {
                    printf("[-] Error reading file\n");
                    return;
                }
                n -= r;
                
                r = write(outfd, buffer, toread);
                if (r != toread) {
                    printf("[-] Error writing file\n");
                    return;
                }
            }
            if (off_cryptid) {
                uint32_t zero=0;
                off_cryptid+=fileoffs;
                printf("[+] Setting the LC_ENCRYPTION_INFO->cryptid to 0 at offset %x\n", off_cryptid);
                if (lseek(outfd, off_cryptid, SEEK_SET) != off_cryptid || write(outfd, &zero, 4) != 4) {
                    printf("[-] Error writing cryptid value\n");
                }
            }
            
            printf("[+] Closing original file\n");
            close(fd);
            printf("[+] Closing dump file\n");
            close(outfd);
            break;
        }

        lc = (struct load_command *)((unsigned char *)lc+lc->cmdsize);
    }

    printf("[*] This mach-o file decrypted done.\n");
        
    NSString* xia0 = @"\nDeveloped By xia0@2019\n"
    
    xia0
    '''
    ret = exeScript(debugger, command_script)

    return ret


def exeScript(debugger,command_script):
    res = lldb.SBCommandReturnObject()
    interpreter = debugger.GetCommandInterpreter()
    interpreter.HandleCommand('exp -lobjc -O -- ' + command_script, res)

    if not res.HasResult():
        # something error
        return res.GetError()
            
    response = res.GetOutput()
    return response

def generateOptions():
    expr_options = lldb.SBExpressionOptions()
    expr_options.SetUnwindOnError(True)
    expr_options.SetLanguage (lldb.eLanguageTypeObjC_plus_plus)
    expr_options.SetCoerceResultToId(False)
    return expr_options

def generate_option_parser():
    usage = "usage: dumpdecrypted [options] args"
    parser = optparse.OptionParser(usage=usage, prog="lookup")

    return parser
