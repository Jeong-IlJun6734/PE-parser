#include <stdio.h>
#include <string.h>
#include <Windows.h>
#include <time.h>

const char* machine_describe(DWORD machine) {
    switch (machine) {
    case 0 :
        return "UNKNOWN : All Machine";
    case 0x184 :
        return "Alpha AXP, 32bits";
    case 0x284 :
        return "Alpha 64 or AXP 64";
    case 0x1d3 :
        return "Matsushita AM33";
    case 0x8664 :
        return "x64";
    case 0x1c0 :
        return "ARM little endian";
    case 0xaa64 :
        return "ARM64 little endian";
    case 0x1c4 :
        return "ARM Thumb-2 little endian";
    case 0xebc :
        return "EFI byte code";
    case 0x14c :
        return "Intel 386 or upper processor - x86";
    case 0x200 :
        return "Intel Itanium processor";
    default :
        return "Don't know";
    }
}

char* characteristic_flag(DWORD characteristic) {
    DWORD relocs_stripped = 0x0001;
    DWORD exec_img = 0x0002;
    DWORD large_addr = 0x0020;
    DWORD x86_32 = 0x0100;
    DWORD debug_stripped = 0x0200;
    DWORD removable = 0x0400;
    DWORD net = 0x0800;
    DWORD sys = 0x1000;
    DWORD dll = 0x2000;
    DWORD up_sys_only = 0x4000;
    
    char mean[1000] = { 0 };
    if (characteristic & relocs_stripped)   strcat(mean, "be loaded at its preferred base address, ");
    if (characteristic & exec_img)          strcat(mean, "the image file is valid and can be run, ");
    if (characteristic & large_addr)        strcat(mean, "Can handle 2GB or more Address, ");
    if (characteristic & x86_32)            strcat(mean, "32bit-word architecture, ");
    if (characteristic & debug_stripped)    strcat(mean, "Debuging information is removed, ");
    if (characteristic & removable)         strcat(mean, "image on removable media, ");
    if (characteristic & net)               strcat(mean, "image on network media, ");
    if (characteristic & sys)               strcat(mean, "system file, ");
    if (characteristic & dll)               strcat(mean, "DLL file, ");
    if (characteristic & up_sys_only)       strcat(mean, "run only a uniprocessor machine, ");

    return mean;
}

const char* subsystem(WORD sub) {
    switch (sub) {
    case 0:
        return "UNKNOWN or Don't need subsystem";
    case 1:
        return "Device driver and Native Window process";
    case 2:
        return "Windows GUI";
    case 3:
        return "Windows CLI";
    case 5:
        return "OS/2 CLI";
    case 7:
        return "Posix CLI";
    case 8:
        return "Native Win9x driver";
    case 9:
        return "Windows CE";
    case 10:
        return "EFI Application";
    case 11:
        return "EFI Application with Booting services";
    case 12:
        return "EFI Application with Runtime services";
    case 13:
        return "EFI ROM Image";
    case 14:
        return "XBOX";
    case 16:
        return "Windows booting Applications";
    }
}

char* S_Characteristics(DWORD characteristic) {
    DWORD CNT_CODE = 0x00000020;
    DWORD INITIALIZED_DATA = 0x00000040;
    DWORD UNINITIALIZED_DATA = 0x00000080;
    DWORD SCN_GPREL = 0x00008000;
    DWORD ALIGN_1BYTES = 0x00100000;
    DWORD ALIGN_2BYTES = 0x00200000;
    DWORD ALIGN_4BYTES = 0x00300000;
    DWORD ALIGN_8BYTES = 0x00400000;
    DWORD ALIGN_16BYTES = 0x00500000;
    DWORD ALIGN_32BYTES = 0x00600000;
    DWORD ALIGN_64BYTES = 0x00700000;
    DWORD ALIGN_128BYTES = 0x00800000;
    DWORD ALIGN_256BYTES = 0x00900000;
    DWORD ALIGN_512BYTES = 0x00A00000;
    DWORD ALIGN_1024BYTES = 0x00B00000;
    DWORD ALIGN_2048BYTES = 0x00C00000;
    DWORD ALIGN_4096BYTES = 0x00D00000;
    DWORD ALIGN_8192BYTES = 0x00E00000;
    DWORD LNK_NRELOC_OVFL = 0x01000000;
    DWORD MEM_DISCARDABLE = 0x02000000;
    DWORD MEM_NOT_CACHED = 0x04000000;
    DWORD MEM_NOT_PAGED = 0x08000000;
    DWORD MEM_SHARED = 0x10000000;
    DWORD MEM_EXECUTE = 0x20000000;
    DWORD MEM_READ = 0x40000000;
    DWORD MEM_WRITE = 0x80000000;


    char mean[1000] = { 0 };
    if (characteristic & CNT_CODE)                  strcat(mean, "includes execute codes, ");
    if (characteristic & INITIALIZED_DATA)          strcat(mean, "includes initialized data, ");
    if (characteristic & UNINITIALIZED_DATA)        strcat(mean, "includes Un-initialized data, ");
    if (characteristic & SCN_GPREL)                 strcat(mean, "data referenced by GP(generic pointer) is in this section, ");
    if (characteristic & ALIGN_1BYTES)              strcat(mean, "aligned by 1 byte, ");
    if (characteristic & ALIGN_2BYTES)              strcat(mean, "aligned by 2 bytes, ");
    if (characteristic & ALIGN_4BYTES)              strcat(mean, "aligned by 4 bytes, ");
    if (characteristic & ALIGN_8BYTES)              strcat(mean, "aligned by 8 bytes, ");
    if (characteristic & ALIGN_16BYTES)             strcat(mean, "aligned by 16 bytes, ");
    if (characteristic & ALIGN_32BYTES)             strcat(mean, "aligned by 32 bytes, ");
    if (characteristic & ALIGN_64BYTES)             strcat(mean, "aligned by 64 bytes, ");
    if (characteristic & ALIGN_128BYTES)            strcat(mean, "aligned by 128 bytes, ");
    if (characteristic & ALIGN_256BYTES)            strcat(mean, "aligned by 256 bytes, ");
    if (characteristic & ALIGN_512BYTES)            strcat(mean, "aligned by 512 bytes, ");
    if (characteristic & ALIGN_1024BYTES)           strcat(mean, "aligned by 1024 bytes, ");
    if (characteristic & ALIGN_2048BYTES)           strcat(mean, "aligned by 2048 bytes, ");
    if (characteristic & ALIGN_4096BYTES)           strcat(mean, "aligned by 4096 bytes, ");
    if (characteristic & ALIGN_8192BYTES)           strcat(mean, "aligned by 8192 bytes, ");
    if (characteristic & LNK_NRELOC_OVFL)           strcat(mean, "contains extended relocations, ");
    if (characteristic & MEM_DISCARDABLE)           strcat(mean, "can be discarded as needed, ");
    if (characteristic & MEM_NOT_CACHED)            strcat(mean, "cannot be cached, ");
    if (characteristic & MEM_NOT_PAGED)             strcat(mean, "is not pageable, ");
    if (characteristic & MEM_SHARED)                strcat(mean, "can be shared in memory, ");
    if (characteristic & MEM_EXECUTE)               strcat(mean, "can be executed as code, ");
    if (characteristic & MEM_READ)                  strcat(mean, "can be read, ");
    if (characteristic & MEM_WRITE)                 strcat(mean, "can be written to, ");

    return mean;
}


int main()
{
    char file_path[5000];

    printf("Path : ");
    scanf("%s", &file_path);

    FILE* fp;
    _IMAGE_DOS_HEADER DOS_header;
    _IMAGE_NT_HEADERS NT_header;
    _IMAGE_SECTION_HEADER Section_header;
    
    //파일 열어보기
    if ((fp = fopen(file_path, "r")) == NULL) {
        printf("Error : can't find file\n File name : %s", file_path);
        return -1;
    }
    //맨 처음으로 옮기고 DOS Header만큼 읽기
    fseek(fp, 0, SEEK_SET);
    fread(&DOS_header, sizeof(_IMAGE_DOS_HEADER),1,fp);

    //PE 포멧에 맞는지 확인 e_magic == MZ
    if (DOS_header.e_magic != 0x5A4D) {
        printf("Error : it is not PE file\n");
        return -1;
    }
    // 맞으면
    else {
        //DOS 헤더 파싱 - 기본으로 붙어있는 stub 메시지나, signature로의 offset 확인
        printf("[DOS_Header]\n");
        printf("DOS Magic :\t\t\t%c%c\n", DOS_header.e_magic,DOS_header.e_magic>>8);
        printf("NT Header offset :\t\t0x%x\n", DOS_header.e_lfanew);
    }

    // NT 헤더 파싱
    // 처음에서부터 DOS 헤더에 있던 offset만큼 움직이고 읽기
    fseek(fp, DOS_header.e_lfanew, SEEK_SET);
    fread(&NT_header, sizeof(_IMAGE_NT_HEADERS), 1, fp);
    printf("\n[NT_Header.FileHeader]\n");
    // Signature == PE
    printf("Signature :\t\t\t%c%c\n", NT_header.Signature, NT_header.Signature>>8);
    printf("Machine :\t\t\t0x%x, mean : %s\n", NT_header.FileHeader.Machine, machine_describe(NT_header.FileHeader.Machine));
    printf("Characteristics : \t\t0x%x, mean :%s\r", NT_header.FileHeader.Characteristics, characteristic_flag(NT_header.FileHeader.Characteristics));
    printf("Number of Sections : \t\t%d\n", NT_header.FileHeader.NumberOfSections);
    printf("Number of Symbols : \t\t%d\n", NT_header.FileHeader.NumberOfSymbols);
    if (NT_header.FileHeader.NumberOfSymbols > 0)
        printf("Porinter to Symtab : \t\t0x%x\n", NT_header.FileHeader.PointerToSymbolTable);

    printf("Size of Optional Header : \t%d bytes\n", NT_header.FileHeader.SizeOfOptionalHeader);
    // 시간 변환
    time_t t = NT_header.FileHeader.TimeDateStamp;
    struct tm* tm = localtime(&t);
    printf("TimeDateStamp :\t\t\t%d-%02d-%02d %02d:%02d:%02d\n", tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec);
    
    printf("\n[NT_Header.OptionalHeader]\n");
    // Optional Header
    printf("Optional Header Magic :\t\t0x%x, mean : %s\n", NT_header.OptionalHeader.Magic, (NT_header.OptionalHeader.Magic == 0x10b) ? "PE32 format" : ((NT_header.OptionalHeader.Magic == 0x20b) ? "PE32+ format" : "others"));
    // 코드(text section) 전체의 크기
    printf("Size of Code :\t\t\t%d bytes\n", NT_header.OptionalHeader.SizeOfCode);
    // 초기화 된 데이터 섹션의 전체 크기
    printf("Size of Initialized Data :\t%d bytes\n", NT_header.OptionalHeader.SizeOfInitializedData);
    // BSS 섹션의 전체 크기
    printf("Size of BSS :\t\t\t%d bytes\n", NT_header.OptionalHeader.SizeOfUninitializedData);
    // 메모리에 로드될 때 베이스를 기준으로하는 진입점. 이미지는 시작주소를 의미. DLL은 선택사항.
    printf("Entry Point Address :\t\t0x%x\n", NT_header.OptionalHeader.AddressOfEntryPoint);
    // 메모리에 로드될 때 코드 섹션의 이미지 베이스. PE32는 뒤에 기본 4바이트 + 4바이트가 추가로 있음.
    printf("Image Base Address :\t\t0x%x\n", NT_header.OptionalHeader.BaseOfCode);
    // 메모리에 로드되는 섹션의 alignment 기본값은 아키텍처의 페이지 크기
    printf("Section Alignment :\t\t%d bytes\n", NT_header.OptionalHeader.SectionAlignment);
    // 파일에서 섹션의 alignment. 기본값은 512byte. if (sectionAlignment < page size) fileAlignment = Section alignment
    printf("File Alignment :\t\t%dbytes\n", NT_header.OptionalHeader.FileAlignment);
    // 메모리에 로드될 때 모든 헤더를 포함한 이미지의 크기. Section Alignment의 배수.
    printf("Size of Image :\t\t\t%d byts\n", NT_header.OptionalHeader.SizeOfImage);
    // 전체 헤더(MS-DOS stub, PE header, Section Header)의 크기. FIleAlignment의 배수로 반올림 된다.
    printf("Size of Headers :\t\t%d byte\n", NT_header.OptionalHeader.SizeOfHeaders);
    // 필요한 서브시스템의 종류
    printf("Sub system :\t\t\t0x%x, mean : %s\n", NT_header.OptionalHeader.Subsystem, subsystem(NT_header.OptionalHeader.Subsystem));
    // 마지막에 있는 데이터 디렉터리의 배열 크기
    // 각 데이터 디렉토리는 DWORD VirtualAddress; DWORD Size로 구성되어있음. 
    printf("Number of Data directory :\t%d\n", NT_header.OptionalHeader.NumberOfRvaAndSizes);

    // Section Header
    printf("\n[Section Header]\n");
    // optional table의 바로 뒤에 있으니까 그대로 읽음. Fileheader의 NumberOfSections만큼 반복..
    int n = 0;
    while (n < NT_header.FileHeader.NumberOfSections) {
        printf("[Section %d]\n", n + 1);
        fread(&Section_header, sizeof(_IMAGE_SECTION_HEADER), 1, fp);
        printf("\tName : \t\t\t%s\n", Section_header.Name);
        // 로드시 섹션의 전체 크기 SizeOfRawData보다 큰경우 0, 개체 파일일 경우도 0, Section_header.MIsc에 있다. PA도 볼 수 있다.
        printf("\tVirtual Size :\t\t0x%x, %d bytes\n", Section_header.Misc.VirtualSize, Section_header.Misc.VirtualSize);
        // 로드시 섹션의 시작 주소        RVA = RAW - Virtual Address + PointerToRawData      RAW = RVA - Virtual Address + PointerToRawData
        // 메모리 상의 시작 주소
        printf("\tVirtualAddress : \t0x%x\n", Section_header.VirtualAddress);
        // 파일에서의 section 크기
        printf("\tRaw Section Size :\t0x%x, %d bytes\n", Section_header.SizeOfRawData, Section_header.SizeOfRawData);
        // 파일에서의 section 시작 위치(RAW)
        printf("\tLocation in File :\t0x%x\n", Section_header.PointerToRawData);
        // section의 특징
        printf("\tCharacteristics :\t0x%x, means : %s", Section_header.Characteristics, S_Characteristics(Section_header.Characteristics));
        printf("\n");
        n++;
    }
}

