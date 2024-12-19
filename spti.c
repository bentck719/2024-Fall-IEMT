#include <windows.h>
#include <devioctl.h>
#include <ntdddisk.h>
#include <ntddscsi.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <strsafe.h>
#include <intsafe.h>
#define _NTSCSI_USER_MODE_
#include <scsi.h>
#include "spti.h"

#define NAME_COUNT  25

#define BOOLEAN_TO_STRING(_b_) ((_b_) ? "True" : "False")

#if defined(_X86_)
#define PAGE_SIZE 0x1000
#define PAGE_SHIFT 12L
#elif defined(_AMD64_)
#define PAGE_SIZE 0x1000
#define PAGE_SHIFT 12L
#elif defined(_IA64_)
#define PAGE_SIZE 0x2000
#define PAGE_SHIFT 13L
#else
// undefined platform?
#define PAGE_SIZE 0x1000
#define PAGE_SHIFT 12L
#endif

LPCSTR BusTypeStrings[] = {
    "Unknown", "Scsi",  "Atapi", "Ata",  "1394",
    "Ssa",     "Fibre", "Usb",   "RAID", "Not Defined",
};
#define NUMBER_OF_BUS_TYPE_STRINGS                                             \
  (sizeof(BusTypeStrings) / sizeof(BusTypeStrings[0]))

VOID __cdecl main(_In_ int argc, _In_z_ char *argv[]) {
  BOOL status = 0;
  DWORD accessMode = 0, shareMode = 0;
  HANDLE fileHandle = NULL;
  ULONG alignmentMask = 0; // default == no alignment requirement
  UCHAR srbType = 0;       // default == SRB_TYPE_SCSI_REQUEST_BLOCK
  PUCHAR dataBuffer = NULL;
  PUCHAR pUnAlignedBuffer = NULL;
  // SCSI_PASS_THROUGH_WITH_BUFFERS sptwb;
  SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER sptdwb;
  // SCSI_PASS_THROUGH_WITH_BUFFERS_EX sptwb_ex;
  // SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER_EX sptdwb_ex;
  CHAR device_name[NAME_COUNT];
  ULONG length = 0, errorCode = 0, returned = 0,
        sectorSize = 512, sectorCount = 0, pattern = 0;
  ULONGLONG lba = 0;

  shareMode = FILE_SHARE_READ | FILE_SHARE_WRITE; // default
  accessMode = GENERIC_WRITE | GENERIC_READ;      // default

  if (argc == 8 || argc == 10) {
    // --disk 2 --read --lba 9 --sector_cnt 32
    //- `--disk` + %d: to select disk (You can get the info under Windows :
    //磁碟管理)
    // - `--write` and `--read`: to select operation to perform
    // - `--lba` + %d: to specify starting logical block address to perform
    // operation on SSD
    // - `--sector_cnt` + %d: the data length from starting logical block
    // address to end
    // - `--data` + %x: set the pattern to be write into SSD (e.g., --data FF
    // will write `FF` into SSD from
    for (int i = 0; i < argc; i++) {
      if (strcmp(argv[i], "--disk") == 0) {
        StringCbPrintf(device_name, sizeof(device_name),
                       "\\\\.\\PHYSICALDRIVE%s", argv[i + 1]);
      } else if (strcmp(argv[i], "--read") == 0) {
        continue;
      } else if (strcmp(argv[i], "--write") == 0) {
        continue;
      } else if (strcmp(argv[i], "--lba") == 0) {
        lba = strtoull(argv[i+1], NULL, 10);
      } else if (strcmp(argv[i], "--sector_cnt") == 0) {
        sectorCount = atoi(argv[i+1]);
      } else if (strcmp(argv[i], "--data") == 0) {
        pattern = strtoul(argv[i+1], NULL, 16);
      }
    }    
  } else {
    printf("Invaild arguments\n");
    return;
  }

  dataBuffer = AllocateAlignedBuffer(sectorSize * sectorCount, alignmentMask, &pUnAlignedBuffer);

  fileHandle = CreateFile(device_name, accessMode, shareMode, NULL, OPEN_EXISTING, 0, NULL);
  if (fileHandle == INVALID_HANDLE_VALUE) {
    errorCode = GetLastError();
    printf("Error opening %s. Error: %d\n", device_name, errorCode);
    PrintError(errorCode);
    return;
  }

  // Get the alignment requirements
  status = QueryPropertyForDevice(fileHandle, &alignmentMask, &srbType);
  if (!status) {
    errorCode = GetLastError();
    printf("Error getting device and/or adapter properties; "
           "error was %d\n",
           errorCode);
    PrintError(errorCode);
    CloseHandle(fileHandle);
    return;
  }

  if (argc == 10) {
    FillMemory(dataBuffer, sectorSize * sectorCount, pattern);
    ZeroMemory(&sptdwb, sizeof(SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER));

    sptdwb.sptd.Length = sizeof(SCSI_PASS_THROUGH_DIRECT);
    sptdwb.sptd.PathId = 0;
    sptdwb.sptd.TargetId = 1;
    sptdwb.sptd.Lun = 0;
    sptdwb.sptd.CdbLength = 16;
    sptdwb.sptd.SenseInfoLength = SPT_SENSE_LENGTH;
    sptdwb.sptd.DataIn = SCSI_IOCTL_DATA_OUT;
    sptdwb.sptd.DataTransferLength = sectorSize * sectorCount;
    sptdwb.sptd.TimeOutValue = 2;
    sptdwb.sptd.DataBuffer = dataBuffer;
    sptdwb.sptd.SenseInfoOffset =
        offsetof(SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER, ucSenseBuf);

    sptdwb.sptd.Cdb[0] = (UCHAR)0x8A;
    sptdwb.sptd.Cdb[1] = (UCHAR)0;
    sptdwb.sptd.Cdb[2] = (UCHAR)((lba >> 56) & 0xFF);
    sptdwb.sptd.Cdb[3] = (UCHAR)((lba >> 48) & 0xFF);
    sptdwb.sptd.Cdb[4] = (UCHAR)((lba >> 40) & 0xFF);
    sptdwb.sptd.Cdb[5] = (UCHAR)((lba >> 32) & 0xFF);
    sptdwb.sptd.Cdb[6] = (UCHAR)((lba >> 24) & 0xFF);
    sptdwb.sptd.Cdb[7] = (UCHAR)((lba >> 16) & 0xFF);
    sptdwb.sptd.Cdb[8] = (UCHAR)((lba >> 8) & 0xFF);
    sptdwb.sptd.Cdb[9] = (UCHAR)(lba & 0xFF);

    sptdwb.sptd.Cdb[10] = (UCHAR)((sectorCount >> 24) & 0xFF);
    sptdwb.sptd.Cdb[11] = (UCHAR)((sectorCount >> 16) & 0xFF);
    sptdwb.sptd.Cdb[12] = (UCHAR)((sectorCount >> 8) & 0xFF);
    sptdwb.sptd.Cdb[13] = (UCHAR)(sectorCount & 0xFF);

    length = sizeof(SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER);
    status = DeviceIoControl(fileHandle, IOCTL_SCSI_PASS_THROUGH_DIRECT, &sptdwb, length, &sptdwb, length, &returned, FALSE);
    PrintStatusResults(status, returned, (PSCSI_PASS_THROUGH_WITH_BUFFERS)&sptdwb, length);
    if ((sptdwb.sptd.ScsiStatus == 0) && (status != 0)) {
        printf("LBA: %llu, SECTOR_CNT: %lu, DATA: %lu, Path: %s, DONE\n", lba, sectorCount, pattern, device_name);
        printf("safe");
    }
    else {
        printf("Write failed, please turn off write protection");
    }
  } else if (argc == 8) {
    ZeroMemory(dataBuffer, sectorSize * sectorCount);
    ZeroMemory(&sptdwb, sizeof(SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER));

    sptdwb.sptd.Length = sizeof(SCSI_PASS_THROUGH_DIRECT);
    sptdwb.sptd.PathId = 0;
    sptdwb.sptd.TargetId = 1;
    sptdwb.sptd.Lun = 0;
    sptdwb.sptd.CdbLength = 16;
    sptdwb.sptd.DataIn = SCSI_IOCTL_DATA_IN;
    sptdwb.sptd.SenseInfoLength = SPT_SENSE_LENGTH;
    sptdwb.sptd.DataTransferLength = sectorSize * sectorCount;
    sptdwb.sptd.TimeOutValue = 2;
    sptdwb.sptd.DataBuffer = dataBuffer;
    sptdwb.sptd.SenseInfoOffset =
        offsetof(SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER, ucSenseBuf);

    // // Set up the READ(16) CDB
    sptdwb.sptd.Cdb[0] = 0x88; // READ(16) opcode
    sptdwb.sptd.Cdb[2] = (UCHAR)((lba >> 56) & 0xFF);
    sptdwb.sptd.Cdb[3] = (UCHAR)((lba >> 48) & 0xFF);
    sptdwb.sptd.Cdb[4] = (UCHAR)((lba >> 40) & 0xFF);
    sptdwb.sptd.Cdb[5] = (UCHAR)((lba >> 32) & 0xFF);
    sptdwb.sptd.Cdb[6] = (UCHAR)((lba >> 24) & 0xFF);
    sptdwb.sptd.Cdb[7] = (UCHAR)((lba >> 16) & 0xFF);
    sptdwb.sptd.Cdb[8] = (UCHAR)((lba >> 8) & 0xFF);
    sptdwb.sptd.Cdb[9] = (UCHAR)(lba & 0xFF);

    sptdwb.sptd.Cdb[10] = (UCHAR)((sectorCount >> 24) & 0xFF);
    sptdwb.sptd.Cdb[11] = (UCHAR)((sectorCount >> 16) & 0xFF);
    sptdwb.sptd.Cdb[12] = (UCHAR)((sectorCount >> 8) & 0xFF);
    sptdwb.sptd.Cdb[13] = (UCHAR)(sectorCount & 0xFF);

    length = sizeof(SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER);
    status = DeviceIoControl(fileHandle, IOCTL_SCSI_PASS_THROUGH_DIRECT, &sptdwb, length, &sptdwb, length, &returned, FALSE);
    PrintStatusResults(status, returned, (PSCSI_PASS_THROUGH_WITH_BUFFERS)&sptdwb, length);
    if ((sptdwb.sptd.ScsiStatus == 0) && (status != 0)) {
      PrintDataBuffer(dataBuffer, sptdwb.sptd.DataTransferLength);
    }
  }

  if (pUnAlignedBuffer != NULL) {
    free(pUnAlignedBuffer);
  }
  CloseHandle(fileHandle);
}

VOID PrintError(ULONG ErrorCode) {
  CHAR errorBuffer[80];
  ULONG count;

  count = FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL, ErrorCode, 0,
                        errorBuffer, sizeof(errorBuffer), NULL);

  if (count != 0) {
    printf("%s\n", errorBuffer);
  } else {
    printf("Format message failed.  Error: %d\n", GetLastError());
  }
}

VOID PrintDataBuffer(_In_reads_(BufferLength) PUCHAR DataBuffer,
                     _In_ ULONG BufferLength) {
  ULONG Cnt;

  printf("      00  01  02  03  04  05  06  07   08  09  0A  0B  0C  0D  0E  "
         "0F\n");
  printf("      "
         "---------------------------------------------------------------\n");
  for (Cnt = 0; Cnt < BufferLength; Cnt++) {
    if ((Cnt) % 16 == 0) {
      printf(" %03X  ", Cnt);
    }
    printf("%02X  ", DataBuffer[Cnt]);
    if ((Cnt + 1) % 8 == 0) {
      printf(" ");
    }
    if ((Cnt + 1) % 16 == 0) {
      printf("\n");
    }
  }
  printf("\n\n");
}

_Success_(return != NULL) _Post_writable_byte_size_(size) PUCHAR
    AllocateAlignedBuffer(_In_ ULONG size, _In_ ULONG AlignmentMask,
                          _Outptr_result_maybenull_ PUCHAR *pUnAlignedBuffer) {
  PUCHAR ptr;

  // NOTE: This routine does not allow for a way to free
  //       memory.  This is an excercise left for the reader.
  UINT_PTR align64 = (UINT_PTR)AlignmentMask;

  if (AlignmentMask == 0) {
    ptr = malloc(size);
    *pUnAlignedBuffer = ptr;
  } else {
    ULONG totalSize;

    (void)ULongAdd(size, AlignmentMask, &totalSize);
    ptr = malloc(totalSize);
    *pUnAlignedBuffer = ptr;
    ptr = (PUCHAR)(((UINT_PTR)ptr + align64) & ~align64);
  }

  if (ptr == NULL) {
    printf("Memory allocation error.  Terminating program\n");
    exit(1);
  } else {
    return ptr;
  }
}

VOID PrintStatusResults(BOOL status, DWORD returned,
                        PSCSI_PASS_THROUGH_WITH_BUFFERS psptwb, ULONG length) {
  ULONG errorCode;

  if (!status) {
    printf("Error: %d  ", errorCode = GetLastError());
    PrintError(errorCode);
    return;
  }
  if (psptwb->spt.ScsiStatus) {
    PrintSenseInfo(psptwb);
    return;
  } else {
    printf("Scsi status: %02Xh, Bytes returned: %Xh, ", psptwb->spt.ScsiStatus,
           returned);
    printf("Data buffer length: %Xh\n\n\n", psptwb->spt.DataTransferLength);
    PrintDataBuffer((PUCHAR)psptwb, length);
  }
}

VOID PrintSenseInfo(PSCSI_PASS_THROUGH_WITH_BUFFERS psptwb) {
  UCHAR i;

  printf("Scsi status: %02Xh\n\n", psptwb->spt.ScsiStatus);
  if (psptwb->spt.SenseInfoLength == 0) {
    return;
  }
  printf("Sense Info -- consult SCSI spec for details\n");
  printf("-------------------------------------------------------------\n");
  for (i = 0; i < psptwb->spt.SenseInfoLength; i++) {
    printf("%02X ", psptwb->ucSenseBuf[i]);
  }
  printf("\n\n");
}

VOID PrintStatusResultsEx(BOOL status, DWORD returned,
                          PSCSI_PASS_THROUGH_WITH_BUFFERS_EX psptwb_ex,
                          ULONG length) {
  ULONG errorCode;

  if (!status) {
    printf("Error: %d  ", errorCode = GetLastError());
    PrintError(errorCode);
    return;
  }
  if (psptwb_ex->spt.ScsiStatus) {
    PrintSenseInfoEx(psptwb_ex);
    return;
  } else {
    printf("Scsi status: %02Xh, Bytes returned: %Xh, ",
           psptwb_ex->spt.ScsiStatus, returned);
    printf("DataOut buffer length: %Xh\n"
           "DataIn buffer length: %Xh\n\n\n",
           psptwb_ex->spt.DataOutTransferLength,
           psptwb_ex->spt.DataInTransferLength);
    PrintDataBuffer((PUCHAR)psptwb_ex, length);
  }
}

VOID PrintSenseInfoEx(PSCSI_PASS_THROUGH_WITH_BUFFERS_EX psptwb_ex) {
  ULONG i;

  printf("Scsi status: %02Xh\n\n", psptwb_ex->spt.ScsiStatus);
  if (psptwb_ex->spt.SenseInfoLength == 0) {
    return;
  }
  printf("Sense Info -- consult SCSI spec for details\n");
  printf("-------------------------------------------------------------\n");
  for (i = 0; i < psptwb_ex->spt.SenseInfoLength; i++) {
    printf("%02X ", psptwb_ex->ucSenseBuf[i]);
  }
  printf("\n\n");
}

_Success_(return ) BOOL QueryPropertyForDevice(_In_ IN HANDLE DeviceHandle,
                                               _Out_ OUT PULONG AlignmentMask,
                                               _Out_ OUT PUCHAR SrbType) {
  PSTORAGE_ADAPTER_DESCRIPTOR adapterDescriptor = NULL;
  PSTORAGE_DEVICE_DESCRIPTOR deviceDescriptor = NULL;
  STORAGE_DESCRIPTOR_HEADER header = {0};

  BOOL ok = TRUE;
  BOOL failed = TRUE;
  ULONG i;

  *AlignmentMask = 0; // default to no alignment
  *SrbType = 0;       // default to SCSI_REQUEST_BLOCK

  // Loop twice:
  //  First, get size required for storage adapter descriptor
  //  Second, allocate and retrieve storage adapter descriptor
  //  Third, get size required for storage device descriptor
  //  Fourth, allocate and retrieve storage device descriptor
  for (i = 0; i < 4; i++) {

    PVOID buffer = NULL;
    ULONG bufferSize = 0;
    ULONG returnedData;

    STORAGE_PROPERTY_QUERY query = {0};

    switch (i) {
    case 0: {
      query.QueryType = PropertyStandardQuery;
      query.PropertyId = StorageAdapterProperty;
      bufferSize = sizeof(STORAGE_DESCRIPTOR_HEADER);
      buffer = &header;
      break;
    }
    case 1: {
      query.QueryType = PropertyStandardQuery;
      query.PropertyId = StorageAdapterProperty;
      bufferSize = header.Size;
      if (bufferSize != 0) {
        adapterDescriptor = LocalAlloc(LPTR, bufferSize);
        if (adapterDescriptor == NULL) {
          goto Cleanup;
        }
      }
      buffer = adapterDescriptor;
      break;
    }
    case 2: {
      query.QueryType = PropertyStandardQuery;
      query.PropertyId = StorageDeviceProperty;
      bufferSize = sizeof(STORAGE_DESCRIPTOR_HEADER);
      buffer = &header;
      break;
    }
    case 3: {
      query.QueryType = PropertyStandardQuery;
      query.PropertyId = StorageDeviceProperty;
      bufferSize = header.Size;

      if (bufferSize != 0) {
        deviceDescriptor = LocalAlloc(LPTR, bufferSize);
        if (deviceDescriptor == NULL) {
          goto Cleanup;
        }
      }
      buffer = deviceDescriptor;
      break;
    }
    }

    // buffer can be NULL if the property queried DNE.
    if (buffer != NULL) {
      RtlZeroMemory(buffer, bufferSize);

      // all setup, do the ioctl
      ok = DeviceIoControl(DeviceHandle, IOCTL_STORAGE_QUERY_PROPERTY, &query,
                           sizeof(STORAGE_PROPERTY_QUERY), buffer, bufferSize,
                           &returnedData, FALSE);
      if (!ok) {
        if (GetLastError() == ERROR_MORE_DATA) {
          // this is ok, we'll ignore it here
        } else if (GetLastError() == ERROR_INVALID_FUNCTION) {
          // this is also ok, the property DNE
        } else if (GetLastError() == ERROR_NOT_SUPPORTED) {
          // this is also ok, the property DNE
        } else {
          // some unexpected error -- exit out
          goto Cleanup;
        }
        // zero it out, just in case it was partially filled in.
        RtlZeroMemory(buffer, bufferSize);
      }
    }
  } // end i loop

  // adapterDescriptor is now allocated and full of data.
  // deviceDescriptor is now allocated and full of data.

  if (adapterDescriptor == NULL) {
    printf("   ***** No adapter descriptor supported on the device *****\n");
  } else {
    // PrintAdapterDescriptor(adapterDescriptor);
    *AlignmentMask = adapterDescriptor->AlignmentMask;
    *SrbType = adapterDescriptor->SrbType;
  }

  if (deviceDescriptor == NULL) {
    printf("   ***** No device descriptor supported on the device  *****\n");
  } else {
    // PrintDeviceDescriptor(deviceDescriptor);
  }

  failed = FALSE;

Cleanup:
  if (adapterDescriptor != NULL) {
    LocalFree(adapterDescriptor);
  }
  if (deviceDescriptor != NULL) {
    LocalFree(deviceDescriptor);
  }
  return (!failed);
}


