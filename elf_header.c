#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libelf.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <inttypes.h>
#include <gelf.h>
#include <stdarg.h>
#include <getopt.h>

#include "elf_header.h"

int get_executable_header(char *file_ptr, Elf64_Ehdr *ptr_p[30]){

        Elf64_Addr entry_point = 0;
        Elf64_Half len_sht = 0;
        Elf64_Half len_pht = 0;

        if ((unsigned char)file_ptr[EI_MAG0] != 0x7F &&
            (unsigned char)file_ptr[EI_MAG1] != 'E' &&
            (unsigned char)file_ptr[EI_MAG2] != 'L' && 
            (unsigned char)file_ptr[EI_MAG3] != 'F'){
                printf("[ERROR] Not an elf file\n");
                return 0;
            }

        printf("Elf header : \n");
        printf("\t[E_IDENT] : \t\t\t%x %x %x %x %x %x %x %x %x %x %x %x %x %x %x\n", (unsigned char)file_ptr[EI_MAG0], (unsigned char)file_ptr[EI_MAG1], (unsigned char)file_ptr[EI_MAG2], (unsigned char)file_ptr[EI_MAG3], (unsigned char)file_ptr[EI_CLASS], (unsigned char)file_ptr[EI_DATA], (unsigned char)file_ptr[EI_VERSION], (unsigned char)file_ptr[EI_OSABI], file_ptr[EI_ABIVERSION], file_ptr[EI_PAD], file_ptr[EI_PAD], file_ptr[EI_PAD], file_ptr[EI_PAD], file_ptr[EI_PAD], file_ptr[EI_PAD]);
        
        /*On a check les 4 premiers bytes */

        if ((unsigned char)file_ptr[EI_CLASS] == ELFCLASS64){
            printf("\tClass : \t\t\tELF64\n");
        }

        else if ((unsigned char)file_ptr[EI_CLASS] == ELFCLASS32){
            printf("\tClass : \t\t\tELF32\n");
        }

        switch ((unsigned char)file_ptr[EI_DATA])
        {
        case ELFDATANONE:
            printf("\tEndianness : \t\t\tNot Endian found\n");
            break;
        
        case ELFDATA2LSB:
            printf("\tEndianness : \t\t\tLittle Endian\n");
            break;

        case ELFDATA2MSB:
            printf("\tEndianness : \t\t\tBig Endian\n");
            break;

        default:
            return 0;
        }

        if ((unsigned char)file_ptr[EI_VERSION] != EV_CURRENT){
            printf("\tVersion : \t\t\t%x (!EV_CURRENT)\n", (unsigned char)file_ptr[EI_VERSION]);
        }

        else{
            printf("\tVersion : \t\t\t%x (EV_CURRENT)\n", (unsigned char)file_ptr[EI_VERSION]);
        }

        switch ((unsigned char)file_ptr[EI_OSABI]){
            case ELFOSABI_NONE:
                printf("\tOS/ABI : \t\t\tUNIX System V ABI\n");

            case ELFOSABI_HPUX:
                printf("\tOS/ABI : \t\t\tHP-UX\n");
                break;

            case ELFOSABI_NETBSD:
                printf("\tOS/ABI : \t\t\tNetBSD\n");
                break;

            case ELFOSABI_GNU:
                printf("\tOS/ABI : \t\t\tGNU ELF Extensions\n");
                break;

            case ELFOSABI_SOLARIS:
                printf("\tOS/ABI : \t\t\tSun Solaris\n");
                break;

            case ELFOSABI_AIX:
                printf("\tOS/ABI : \t\t\tIBM AIX\n");
                break;

            case ELFOSABI_IRIX:
                printf("\tOS/ABI : \t\t\tSGI Irix\n");
                break;

            case ELFOSABI_FREEBSD:
                printf("\tOS/ABI : \t\t\tFreeBSD\n");
                break;

            case ELFOSABI_TRU64:
                printf("\tOS/ABI : \t\t\tCompaq TRU64 UNIX\n");
                break;

            case ELFOSABI_MODESTO:
                printf("\tOS/ABI : \t\t\tNovell Modesto\n");
                break;

            case ELFOSABI_OPENBSD:
                printf("\tOS/ABI : \t\t\tOpenBSD\n");
                break;

            case ELFOSABI_ARM_AEABI:
                printf("\tOS/ABI : \t\t\tARM EABI\n");
                break;

            case ELFOSABI_ARM:
                printf("\tOS/ABI : \t\t\tARM\n");
                break;

            case ELFOSABI_STANDALONE:
                printf("\tOS/ABI : \t\t\tStandalone (embedded) application\n");
                break;

            default:
                printf("\tOS/ABI : \t\t\tOs has not been recognized\n");
                break;
        }

        printf("\tABI Version : \t\t\t%x\n", (unsigned char)file_ptr[EI_ABIVERSION]);

        printf("\t[EI_PAD] \t\t\t ");
        for (int i=15; i>9; i--){
            printf(" %x", (unsigned int)file_ptr[EI_PAD]);
        }
        printf("\n");

        /*On a finis d'analyser le E_IDENT sur 16 bytes */

        // ==================================================================================================================

        Elf64_Ehdr *ptr = (Elf64_Ehdr*)file_ptr;

        switch (ptr->e_type)
        {
        case ET_NONE:
            printf("\tType : \t\t\t\tNo file type\n");
            break;
        
        case ET_REL:
            printf("\tType : \t\t\t\tRelocatable file\n");
            break;

        case ET_EXEC:
            printf("\tType : \t\t\t\tExecutable file\n");
            break;

        case ET_DYN:
            printf("\tType : \t\t\t\tShared object file\n");
            break;

        case ET_CORE:
            printf("\tType : \t\t\t\tCore file\n");
            break;

        case ET_NUM:
            printf("\tType : \t\t\t\tNumber of defined types\n");
            break;

        case ET_LOOS:
            printf("\tType : \t\t\t\tOS-specific range start\n");
            break;

        case ET_HIOS:
            printf("\tType : \t\t\t\tOS-specific range end\n");
            break;

        case ET_LOPROC:
            printf("\tType : \t\t\t\tProcessor-specific range start\n");
            break;

        case ET_HIPROC:
            printf("\tType : \t\t\t\tProcessor-specific range end\n");
            break;

        default:
            printf("\tType : \t\t\t\tType not found\n");
            break;
        }

        /*On check mtn le e_machine */

        switch (ptr->e_machine)
        {
        case EM_NONE:
            printf("\tMachine : \t\t\tNo machine\n");
            break;
        
        case EM_M32:
            printf("\tMachine : \t\t\tAT&T WE 32100\n");
            break;

        case EM_SPARC:
            printf("\tMachine : \t\t\tSUN SPARC\n");
            break;

        case EM_386:
            printf("\tMachine : \t\t\tIntel 80386\n");
            break;

        case EM_68K:
            printf("\tMachine : \t\t\tMotorola m68k family\n");
            break;

        case EM_88K:
            printf("\tMachine : \t\t\tMotorola m88k family\n");
            break;

        case EM_IAMCU:
            printf("\tMachine : \t\t\tIntel MCU\n");
            break;

        case EM_860:
            printf("\tMachine : \t\t\tIntel 80860\n");
            break;

        case EM_MIPS:
            printf("\tMachine : \t\t\tMIPS R3000 big-endian\n");
            break;

        case EM_S370:
            printf("\tMachine : \t\t\tIBM System/370\n");
            break;

        case EM_MIPS_RS3_LE:
            printf("\tMachine : \t\t\tMIPS R3000 little-endian\n");
            break;

        case EM_PARISC:
            printf("\tMachine : \t\t\tHPPA\n");
            break;

        case EM_VPP500:
            printf("\tMachine : \t\t\tFujitsu VPP500\n");
            break;

        case EM_SPARC32PLUS:
            printf("\tMachine : \t\t\tSun's v8plus\n");
            break;

        case EM_960:
            printf("\tMachine : \t\t\tIntel 80960\n");
            break;

        case EM_PPC:
            printf("\tMachine : \t\t\tPowerPC\n");
            break;

        case EM_PPC64:
            printf("\tMachine : \t\t\tPowerPC 64-bit\n");
            break;

        case EM_S390:
            printf("\tMachine : \t\t\tIBM S390\n");
            break;

        case EM_SPU:
            printf("\tMachine : \t\t\tIBM SPU/SPC\n");
            break;

        case EM_V800:
            printf("\tMachine : \t\t\tNEC V800 series\n");
            break;

        case EM_FR20:
            printf("\tMachine : \t\t\tFujitsu FR20\n");
            break;

        case EM_RH32:
            printf("\tMachine : \t\t\tTRW RH-32\n");
            break;

        case EM_RCE:
            printf("\tMachine : \t\t\tMotorola RCE\n");
            break;

        case EM_ARM:
            printf("\tMachine : \t\t\tARM\n");
            break;

        case EM_FAKE_ALPHA:
            printf("\tMachine : \t\t\tDigital Alpha\n");
            break;

        case EM_SH:
            printf("\tMachine : \t\t\tHitachi SH\n");
            break;

        case EM_SPARCV9:
            printf("\tMachine : \t\t\tSPARC v9 64-bit\n");
            break;

        case EM_TRICORE:
            printf("\tMachine : \t\t\tSiemens Tricore\n");
            break;

        case EM_ARC:
            printf("\tMachine : \t\t\tArgonaut RISC Core\n");
            break;

        case EM_H8_300:
            printf("\tMachine : \t\t\tHitachi H8/300\n");
            break;

        case EM_H8_300H:
            printf("\tMachine : \t\t\tHitachi H8/300H\n");
            break;

        case EM_H8S:
            printf("\tMachine : \t\t\tHitachi H8S\n");
            break;

        case EM_H8_500:
            printf("\tMachine : \t\t\tHitachi H8/500\n");
            break;

        case EM_IA_64:
            printf("\tMachine : \t\t\tIntel Merced\n");
            break;

        case EM_MIPS_X:
            printf("\tMachine : \t\t\tStanford MIPS-X\n");
            break;

        case EM_COLDFIRE:
            printf("\tMachine : \t\t\tMotorola Coldfire\n");
            break;

        case EM_68HC12:
            printf("\tMachine : \t\t\tMotorola M68HC12\n");
            break;

        case EM_MMA:
            printf("\tMachine : \t\t\tFujitsu MMA Multimedia Accelerator\n");
            break;

        case EM_PCP:
            printf("\tMachine : \t\t\tSiemens PCP\n");
            break;

        case EM_NCPU:
            printf("\tMachine : \t\t\tSony nCPU embeeded RISC\n");
            break;

        case EM_NDR1:
            printf("\tMachine : \t\t\tDenso NDR1 microprocessor\n");
            break;

        case EM_STARCORE:
            printf("\tMachine : \t\t\tMotorola Start*Core processor\n");
            break;

        case EM_ME16:
            printf("\tMachine : \t\t\tToyota ME16 processor\n");
            break;

        case EM_ST100:
            printf("\tMachine : \t\t\tSTMicroelectronic ST100 processor\n");
            break;

        case EM_TINYJ:
            printf("\tMachine : \t\t\tAdvanced Logic Corp. Tinyj emb.fam\n");
            break;

        case EM_X86_64:
            printf("\tMachine : \t\t\tAMD x86-64 architecture\n");
            break;

        case EM_PDSP:
            printf("\tMachine : \t\t\tSony DSP Processor\n");
            break;

        case EM_PDP10:
            printf("\tMachine : \t\t\tDigital PDP-10\n");
            break;

        case EM_PDP11:
            printf("\tMachine : \t\t\tDigital PDP-11\n");
            break;

        case EM_FX66:
            printf("\tMachine : \t\t\tSiemens FX66 microcontroller\n");
            break;

        case EM_ST9PLUS:
            printf("\tMachine : \t\t\tSTMicroelectronics ST9+ 8/16 mc\n");
            break;

        case EM_ST7:
            printf("\tMachine : \t\t\tSTmicroelectronics ST7 8 bit mc\n");
            break;

        case EM_68HC16:
            printf("\tMachine : \t\t\tMotorola MC68HC16 microcontroller\n");
            break;

        case EM_68HC11:
            printf("\tMachine : \t\t\tMotorola MC68HC11 microcontroller\n");
            break;

        case EM_68HC08:
            printf("\tMachine : \t\t\tMotorola MC68HC08 microcontroller\n");
            break;
        
        case EM_68HC05:
            printf("\tMachine : \t\t\tMotorola MC68HC05 microcontroller\n");
            break;

        case EM_SVX:
            printf("\tMachine : \t\t\tSilicon Graphics SVx\n");
            break;

        case EM_ST19:
            printf("\tMachine : \t\t\tSTMicroelectronics ST19 8 bit mc\n");
            break;

        case EM_VAX:
            printf("\tMachine : \t\t\tDigital VAX\n");
            break;

        case EM_CRIS:
            printf("\tMachine : \t\t\tAxis Communications 32-bit emb.proc\n");
            break;

        case EM_JAVELIN:
            printf("\tMachine : \t\t\tInfineon Technologies 32-bit emb.proc\n");
            break;

        case EM_FIREPATH:
            printf("\tMachine : \t\t\tElement 14 64-bit DSP Processor\n");
            break;

        case EM_ZSP:
            printf("\tMachine : \t\t\tLSI Logic 16-bit DSP Processor\n");
            break;

        case EM_MMIX:
            printf("\tMachine : \t\t\tDonald Knuth's educational 64-bit proc\n");
            break;

        case EM_HUANY:
            printf("\tMachine : \t\t\tHarvard University machine-independent object files\n");
            break;

        case EM_PRISM:
            printf("\tMachine : \t\t\tSiTera Prism\n");
            break;

        case EM_AVR:
            printf("\tMachine : \t\t\tAtmel AVR 8-bit microcontroller\n");
            break;

        case EM_FR30:
            printf("\tMachine : \t\t\tFujitsu FR30\n");
            break;

        case EM_D10V:
            printf("\tMachine : \t\t\tMitsubishi D10V\n");
            break;

        case EM_D30V:
            printf("\tMachine : \t\t\tMitsubishi D30V\n");
            break;

        case EM_V850:
            printf("\tMachine : \t\t\tNEC v850\n");
            break;

        case EM_M32R:
            printf("\tMachine : \t\t\tMitsubishi M32R\n");
            break;

        case EM_MN10300:
            printf("\tMachine : \t\t\tMatsushita MN10300\n");
            break;
        
        case EM_MN10200:
            printf("\tMachine : \t\t\tMatsushita MN10200\n");
            break;

        case EM_PJ:
            printf("\tMachine : \t\t\tpicoJava\n");
            break;

        case EM_OPENRISC:
            printf("\tMachine : \t\t\tOpenRISC 32-bit embedded processor\n");
            break;

        case EM_ARC_COMPACT:
            printf("\tMachine : \t\t\tARC International ARCompact\n");
            break;

        case EM_XTENSA:
            printf("\tMachine : \t\t\tTensilica Xtensa Architecture\n");
            break;

        case EM_VIDEOCORE:
            printf("\tMachine : \t\t\tAlphamosaic VideoCore\n");
            break;

        case EM_TMM_GPP:
            printf("\tMachine : \t\t\tThompson Multimedia General Purpose Proc\n");
            break;

        case EM_NS32K:
            printf("\tMachine : \t\t\tNational Semi. 32000\n");
            break;

        case EM_TPC:
            printf("\tMachine : \t\t\tTenor Network TPC\n");
            break;

        case EM_SNP1K:
            printf("\tMachine : \t\t\tTrebia SNP 1000\n");
            break;

        case EM_ST200:
            printf("\tMachine : \t\t\tSTMicroelectronics ST200\n");
            break;

        case EM_IP2K:
            printf("\tMachine : \t\t\tUbicom IP2xxx\n");
            break;

        case EM_MAX:
            printf("\tMachine : \t\t\tMAX processor\n");
            break;

        case EM_CR:
            printf("\tMachine : \t\t\tNational Semi. CompactRISC\n");
            break;
        
        case EM_F2MC16:
            printf("\tMachine : \t\t\tFujitsu F2MC16\n");
            break;

        case EM_MSP430:
            printf("\tMachine : \t\t\tTexas Instruments msp430\n");
            break;

        case EM_BLACKFIN:
            printf("\tMachine : \t\t\tAnalog Devices Blackfin DSP\n");
            break;
        
        case EM_SE_C33:
            printf("\tMachine : \t\t\tSeiko Epson S1C33 family\n");
            break;
        
        case EM_SEP:
            printf("\tMachine : \t\t\tSharp embedded microprocessor\n");
            break;
        
        case EM_ARCA:
            printf("\tMachine : \t\t\tArca RISC\n");
            break;
        
        case EM_UNICORE:
            printf("\tMachine : \t\t\tPKU-Unity & MPRC Peking Uni. mc series\n");
            break;
        
        case EM_EXCESS:
            printf("\tMachine : \t\t\teXcess configurable cpu\n");
            break;

        case EM_DXP:
            printf("\tMachine : \t\t\tIcera Semi. Deep Execution Processor\n");
            break;

        case EM_ALTERA_NIOS2:
            printf("\tMachine : \t\t\tAltera Nios II\n");
            break;

        case EM_CRX:
            printf("\tMachine : \t\t\tNational Semi. CompactRISC CRX\n");
            break;

        case EM_XGATE:
            printf("\tMachine : \t\t\tMotorola XGATE\n");
            break;

        case EM_C166:
            printf("\tMachine : \t\t\tInfineon C16x/XC16x\n");
            break;

        case EM_M16C:
            printf("\tMachine : \t\t\tRenesas M16C\n");
            break;

        case EM_DSPIC30F:
            printf("\tMachine : \t\t\tMicrochip Technology dsPIC30F\n");
            break;

        case EM_CE:
            printf("\tMachine : \t\t\tFreescale Communication Engine RISC\n");
            break;

        case EM_M32C:
            printf("\tMachine : \t\t\tRenesas M32C\n");
            break;

        case EM_TSK3000:
            printf("\tMachine : \t\t\tAltium TSK3000\n");
            break;

        case EM_RS08:
            printf("\tMachine : \t\t\tFreescale RS08\n");
            break;

        case EM_SHARC:
            printf("\tMachine : \t\t\tAnalog Devices SHARC family\n");
            break;

        case EM_ECOG2:
            printf("\tMachine : \t\t\tCyan Technology eCOG2\n");
            break;

        case EM_SCORE7:
            printf("\tMachine : \t\t\tSunplus S+core7 RISC\n");
            break;

        case EM_DSP24:
            printf("\tMachine : \t\t\tNew Japan Radio (NJR) 24-bit DSP\n");
            break;

        case EM_VIDEOCORE3:
            printf("\tMachine : \t\t\tBroadcom VideoCore III\n");
            break;

        case EM_LATTICEMICO32:
            printf("\tMachine : \t\t\tRISC for Lattice FPGA\n");
            break;

        case EM_SE_C17:
            printf("\tMachine : \t\t\tSeiko Epson C17\n");
            break;

        case EM_TI_C6000:
            printf("\tMachine : \t\t\tTexas Instruments TMS320C6000 DSP\n");
            break;

        case EM_TI_C2000:
            printf("\tMachine : \t\t\tTexas Instruments TMS320C2000 DSP\n");
            break;

        case EM_TI_C5500:
            printf("\tMachine : \t\t\tTexas Instruments TMS320C55x DSP\n");
            break;

        case EM_TI_ARP32:
            printf("\tMachine : \t\t\tTexas Instruments App. Specific RISC\n");
            break;

        case EM_TI_PRU:
            printf("\tMachine : \t\t\tTexas Instruments Prog. Realtime Unit\n");
            break;
        
        case EM_MMDSP_PLUS:
            printf("\tMachine : \t\t\tSTMicroelectronics 64bit VLIW DSP\n");
            break;

        case EM_CYPRESS_M8C:
            printf("\tMachine : \t\t\tRenesas R32C\n");
            break;

        case EM_R32C:
            printf("\tMachine : \t\t\tMotorola XGATE\n");
            break;

        case EM_TRIMEDIA:
            printf("\tMachine : \t\t\tNXP Semi. TriMedia\n");
            break;

        case EM_QDSP6:
            printf("\tMachine : \t\t\tQUALCOMM DSP6\n");
            break;

        case EM_8051:
            printf("\tMachine : \t\t\tIntel 8051 and variants\n");
            break;

        case EM_STXP7X:
            printf("\tMachine : \t\t\tSTMicroelectronics STxP7x\n");
            break;

        case EM_NDS32:
            printf("\tMachine : \t\t\tAndes Tech. compact code emb. RISC\n");
            break;

        case EM_ECOG1X:
            printf("\tMachine : \t\t\tCyan Technology eCOG1X\n");
            break;

        case EM_MAXQ30:
            printf("\tMachine : \t\t\tDallas Semi. MAXQ30 mc\n");
            break;

        case EM_XIMO16:
            printf("\tMachine : \t\t\tNew Japan Radio (NJR) 16-bit DSP\n");
            break;

        case EM_MANIK:
            printf("\tMachine : \t\t\tM2000 Reconfigurable RISC\n");
            break;

        case EM_CRAYNV2:
            printf("\tMachine : \t\t\tCray NV2 vector architecture\n");
            break;

        case EM_RX:
            printf("\tMachine : \t\t\tRenesas RX\n");
            break;

        case EM_METAG:
            printf("\tMachine : \t\t\tImagination Tech. META\n");
            break;

        case EM_MCST_ELBRUS:
            printf("\tMachine : \t\t\tMCST Elbrus\n");
            break;

        case EM_ECOG16:
            printf("\tMachine : \t\t\tCyan Technology eCOG16\n");
            break;

        case EM_CR16:
            printf("\tMachine : \t\t\tNational Semi. CompactRISC CR16\n");
            break;

        case EM_ETPU:
            printf("\tMachine : \t\t\tFreescale Extended Time Processing Unit\n");
            break;

        case EM_SLE9X:
            printf("\tMachine : \t\t\tInfineon Tech. SLE9X\n");
            break;

        case EM_L10M:
            printf("\tMachine : \t\t\tIntel L10M\n");
            break;

        case EM_K10M:
            printf("\tMachine : \t\t\tMotorola XGATE\n");
            break;

        case EM_AARCH64:
            printf("\tMachine : \t\t\tARM AARCH64\n");
            break;

        case EM_AVR32:
            printf("\tMachine : \t\t\tAmtel 32-bit microprocessor\n");
            break;

        case EM_STM8:
            printf("\tMachine : \t\t\tSTMicroelectronics STM8\n");
            break;

        case EM_TILE64:
            printf("\tMachine : \t\t\tTileta TILE64\n");
            break;

        case EM_TILEPRO:
            printf("\tMachine : \t\t\tTilera TILEPro\n");
            break;

        case EM_MICROBLAZE:
            printf("\tMachine : \t\t\tXilinx MicroBlaze\n");
            break;

        case EM_CUDA:
            printf("\tMachine : \t\t\tNVIDIA CUDA\n");
            break;

        case EM_TILEGX:
            printf("\tMachine : \t\t\tTilera TILE-Gx\n");
            break;

        case EM_CLOUDSHIELD:
            printf("\tMachine : \t\t\tCloudShield\n");
            break;

        case EM_COREA_1ST:
            printf("\tMachine : \t\t\tKIPO-KAIST Core-A 1st gen.\n");
            break;

        case EM_COREA_2ND:
            printf("\tMachine : \t\t\tKIPO-KAIST Core-A 2nd gen.\n");
            break;

        case EM_ARC_COMPACT2:
            printf("\tMachine : \t\t\tSynopsys ARCompact V2\n");
            break;

        case EM_OPEN8:
            printf("\tMachine : \t\t\tOpen8 RISC\n");
            break;

        case EM_RL78:
            printf("\tMachine : \t\t\tRenesas RL78\n");
            break;

        case EM_VIDEOCORE5:
            printf("\tMachine : \t\t\tBroadcom VideoCore V\n");
            break;

        case EM_78KOR:
            printf("\tMachine : \t\t\tRenesas 78KOR\n");
            break;

        case EM_BA1:
            printf("\tMachine : \t\t\tBeyond BA1\n");
            break;

        case EM_BA2:
            printf("\tMachine : \t\t\tBeyond BA2\n");
            break;

        case EM_XCORE:
            printf("\tMachine : \t\t\tXMOS xCORE\n");
            break;

        case EM_MCHP_PIC:
            printf("\tMachine : \t\t\tMicrochip 8-bit PIC(r)\n");
            break;

        case EM_KM32:
            printf("\tMachine : \t\t\tKM211 KM32\n");
            break;

        case EM_KMX32:
            printf("\tMachine : \t\t\tKM211 KMX32\n");
            break;

        case EM_EMX16:
            printf("\tMachine : \t\t\tKM211 KMX16\n");
            break;

        case EM_EMX8:
            printf("\tMachine : \t\t\tKM211 KMX8\n");
            break;

        case EM_KVARC:
            printf("\tMachine : \t\t\tKM211 KVARC\n");
            break;

        case EM_CDP:
            printf("\tMachine : \t\t\tPaneve CDP\n");
            break;

        case EM_COGE:
            printf("\tMachine : \t\t\tCognitive Smart Memory Processor\n");
            break;

        case EM_COOL:
            printf("\tMachine : \t\t\tBluechip CoolEngine\n");
            break;

        case EM_NORC:
            printf("\tMachine : \t\t\tNanoradio Optimized RISC\n");
            break;

        case EM_CSR_KALIMBA:
            printf("\tMachine : \t\t\tCSR Kalimba\n");
            break;

        case EM_Z80:
            printf("\tMachine : \t\t\tZilog Z80\n");
            break;

        case EM_VISIUM:
            printf("\tMachine : \t\t\tControls and Data Services VISIUMcore\n");
            break;

        case EM_FT32:
            printf("\tMachine : \t\t\tFTDI Chip FT32\n");
            break;

        case EM_MOXIE:
            printf("\tMachine : \t\t\tMoxie processor\n");
            break;
        
        case EM_AMDGPU:
            printf("\tMachine : \t\t\tAMD GPU\n");
            break;

        case EM_RISCV:
            printf("\tMachine : \t\t\tRISC-V\n");
            break;

        case EM_BPF:
            printf("\tMachine : \t\t\tLinux BPF -- in-kernel virtual machine\n");
            break;

        default:
            printf("\tMachine : \t\t\tE_MACHINE not recognized\n");
            break;
        }
        
        /*On a ENFIN finis de check le E_MACHINE
            On passe à l'octet suivant, le e_version */

        switch (ptr->e_version)
        {
        case EV_NONE:
            printf("\tVersion : \t\t\tInvalid ELF version\n");
            break;

        case EV_CURRENT:
            printf("\tVersion : \t\t\tCurrent version\n");
            break;

        case EV_NUM:
            printf("\tVersion : \t\t\tI can't find any E_VERSION\n");
            break;
        
        default:
            printf("\tVersion : \t\t\tE_VERSION not recognized\n");
            break;
        }

        /*On a check la version mtn on fait l'ep */

        if (ptr->e_entry){
            printf("\tEntrypoint : \t\t\t0x%lx\n", ptr->e_entry);
            entry_point = ptr->e_entry;

        }

        else
        {
            printf("\tEntrypoint : \t\t\tEntrypoint not found\n");
        }
        
        /*On a fait l'ep mtn on fait  le e_phoff*/

        if (ptr->e_phoff){
            printf("\tProgramm header : \t\t0x%lx (offset)\n", ptr->e_phoff);
        }

        else
        {
            printf("\tProgramm header : \t\tNULL\n");
        }
        
        // section header offset

        if (ptr->e_shoff){
            printf("\tSection Header Table : \t\t0x%lx (offset)\n", ptr->e_shoff);
        }

        else{
            printf("\tSection Header Table : \t\tNULL\n");
        }

        // on check les flags

        switch (ptr->e_flags)
        {
        case EF_CPU32:
            printf("\tFlags : \t\t\t0x00810000 (EF_CPU32)\n");
            break;

        case EF_SPARCV9_MM:
            printf("\tFlags : \t\t\t0x3 (EF_SPARCV9_MM)\n");
            break;

        case EF_SPARCV9_TSO:
            printf("\tFlags : \t\t\t0x0 (NULL)\n");
            break;

        case EF_SPARCV9_PSO:
            printf("\tFlags : \t\t\t0x1 (EF_SPARCV9_PSO)\n");
            break;

        case EF_SPARCV9_RMO:
            printf("\tFlags : \t\t\t0x2 (EF_SPARCV9_RMO)\n");
            break;

        case EF_SPARC_LEDATA:
            printf("\tFlags : \t\t\t0x800000 (little endian data)\n");
            break;

        case EF_SPARC_EXT_MASK:
            printf("\tFlags : \t\t\t0xFFFF00\n");
            break;

        case EF_SPARC_32PLUS:
            printf("\tFlags : \t\t\t0x000100 (generic V8+ features)\n");
            break;

        case EF_SPARC_SUN_US1:
            printf("\tFlags : \t\t\t0x000200 (Sun UltraSPARC1 extensions)\n");
            break;

        case EF_SPARC_HAL_R1:
            printf("\tFlags : \t\t\t0x000400 (HAL R1 extensions)\n");
            break;

        case EF_SPARC_SUN_US3:
            printf("\tFlags : \t\t\t0x000800 (Sun UltraSPARCIII extensions)\n");
            break;
        
        default:
            printf("\tFlags : \t\t\t0x%x (flag is not recognized)\n", ptr->e_flags);
            break;
        }


        // e_ehsize

        printf("\tExecutable header : \t\t0x%x bytes\n", ptr->e_ehsize);

        // e_phentsize, len de une entry 

        printf("\tProgramm Header length : \t0x%x (1 entry)\n", ptr->e_phentsize);

        // e_phnum nombre de entry

        printf("\tNumber of entry : \t\t0x%x (in the programm header)\n", ptr->e_phnum);

        // On calcul la taille de la programm header table

        len_pht = ptr->e_phentsize * ptr->e_phnum;

        printf("\tProgramm Header Table : \t0x%x bytes\n", len_pht);

        // e_shentsize len de une entrée dans le Section header

        printf("\tSection Header length : \t0x%x (1 entry)\n", ptr->e_shentsize);

        // e_shnum le nombre d'entrées dans la table "section header"

        printf("\tNumber of entry : \t\t0x%x\n", ptr->e_shnum);

        // On calcul la len du section header

        len_sht = ptr->e_shentsize * ptr->e_shnum;

        printf("\tSection Header length : \t0x%x\n", len_sht);

        // e_shstrnx

        printf("\tShtrndx : \t\t\t0x%x\n", ptr->e_shstrndx);

        for (size_t i = 0; i < sizeof(Elf64_Ehdr); i++)
        {
            ptr_p[i] = (Elf64_Ehdr *) (char *) file_ptr + i;
        }

        return 0;
        
    }