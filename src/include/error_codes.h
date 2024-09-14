#ifndef ERROR_CODES
#include <linux/types.h>  // for uint32_t
#include <linux/stddef.h> //for size_t


#define KN_STATUS u32


#define ERROR_CODES

#define SUCCESS_ERROR               0x0
#define SUCCESS_ERROR_MSG "OK"
#define ERROR                       0xFFFFFFFF
#define ERROR_MSG "ERROR"
#define TCP_HEADER_GET_ERROR        0xFFFFFFFE
#define TCP_HEADER_GET_ERROR_MSG "failed to get tcp header"
#define UDP_HEADER_GET_ERROR        0xFFFFFFFD
#define UDP_HEADER_GET_ERROR_MSG "failed to get udp header"
#define ICMP_HEADER_GET_ERROR       0xFFFFFFFC
#define ICMP_HEADER_GET_ERROR_MSG "failed to get icmp header"
#define IP_HEADER_GET_ERROR         0xFFFFFFFB
#define IP_HEADER_GET_ERROR_MSG "failed to get ip header"
#define PROTOCOL_SELECTION_ERROR    0xFFFFFFFA
#define PROTOCOL_SELECTION_ERROR_MSG "protocol selection error"
#define PORT_SELECTION_ERROR        0xFFFFFFF9
#define PORT_SELECTION_ERROR_MSG "port selection error"
#define CHOSEN_ANOTHER_PORT_ERROR   0xFFFFFFF8
#define CHOSEN_ANOTHER_PORT_ERROR_MSG "chosen another port error"
#define DOSNT_CONTAIN_DATA_ERROR    0xFFFFFFF7
#define DOSNT_CONTAIN_DATA_ERROR_MSG "dosn't contain data error"
#define ALLOCATE_MEMORY_ERROR       0xFFFFFFF6
#define ALLOCATE_MEMORY_ERROR_MSG "allocate memory error"
#define COPY_BUFFER_ERROR           0xFFFFFFF5
#define COPY_BUFFER_ERROR_MSG "copy buffer error"
#define DATA_ISNT_CORRECT_ERROR           0xFFFFFFF4
#define DATA_ISNT_CORRECT_ERROR_MSG "data is not correct"

#define DATA_LINEAROZED_ERROR   0xFFFFFFF3
#define DATA_LINEAROZED_ERROR_MSG "data cannot be linearized"


#define UNEXPECTED_ERROR            0xF0000000
#define UNEXPECTED_ERROR_MSG "Unknown error"

 
 #define GET_ERROR_MSG(error_code) error_code##_MSG

 #define ERROR_TABLE_RAW(error_code) { error_code, error_code##_MSG },


typedef struct {
    uint32_t error_code;
    const char* error_msg;
} ErrorEntry;



 
 
static inline const unsigned char* get_error_message(uint32_t ecode) {

    ErrorEntry error_table[] = {
        ERROR_TABLE_RAW(SUCCESS_ERROR)
        ERROR_TABLE_RAW(ERROR)
        ERROR_TABLE_RAW(TCP_HEADER_GET_ERROR)
        ERROR_TABLE_RAW(UDP_HEADER_GET_ERROR)
        ERROR_TABLE_RAW(ICMP_HEADER_GET_ERROR)
        ERROR_TABLE_RAW(IP_HEADER_GET_ERROR)
        ERROR_TABLE_RAW(PROTOCOL_SELECTION_ERROR)
        ERROR_TABLE_RAW(PORT_SELECTION_ERROR)
        ERROR_TABLE_RAW(CHOSEN_ANOTHER_PORT_ERROR)
        ERROR_TABLE_RAW(DOSNT_CONTAIN_DATA_ERROR)
        ERROR_TABLE_RAW(ALLOCATE_MEMORY_ERROR)
        ERROR_TABLE_RAW(COPY_BUFFER_ERROR)
        ERROR_TABLE_RAW(UNEXPECTED_ERROR)
    };
 
    size_t num_errors = sizeof(error_table) / sizeof(ErrorEntry);
    for (size_t i = 0; i < num_errors; i++) 
        if (error_table[i].error_code == ecode) 
            return error_table[i].error_msg;

    return UNEXPECTED_ERROR_MSG;
}
  

#endif //ERROR_CODES_