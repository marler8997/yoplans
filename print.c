#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>

#include "global.h"

#include "log.macros.c"

int printFile(char *filename)
{
  int bytesRead,bytesWritten,fileHandle;
  char buffer[PRINT_FILE_BUFFER_SIZE];

  fflush(stdout); // Need to flush stdout here because I use the write method
                  // to write to stdout instead of a stdio.h method (printf,fwrite, etc.)
                  // Therefore, if stdout has not been flushed yet, then calling 
                  // write will circumvent the bufferend data written using stdio.h.

  fileHandle = open(filename, O_RDONLY);
  if(fileHandle == -1) {
    logError("open of '%s' returned -1", filename);
    printf("<html><head><title>OPEN ERROR</title></head><body><h1>SERVER ERROR</h1></body></html>\n");
    return -1;
  }
  
  while(1) {
    bytesRead = read(fileHandle, buffer, PRINT_FILE_BUFFER_SIZE);
    if(bytesRead <= 0) {
      if(bytesRead < 0) logError("read returned %d", bytesRead);
      break;
    }
    bytesWritten = write(1, buffer, bytesRead);
    if(bytesWritten < bytesRead) {
      logError("write returned %d, but expected %d", bytesWritten, bytesRead);
      break;
    }
  }    
  
  close(fileHandle);
  return 0;
}
