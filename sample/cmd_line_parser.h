//
// cmd_line_parser.h
//

#ifndef __CMD_LINE_PARSER_H__
#define __CMD_LINE_PARSER_H__

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

struct cmd_line_info {
    char *server_addr;
    char *server_port;
    char *request_path;
    char *root_cert_file;
    char *out_put_file;
    int dump_level;
    bool help_flag;
};

struct cmd_line_info * cmd_line_info_create(int argc, char * const argv[]);
void cmd_line_info_destroy(struct cmd_line_info *info);
const char * app_name(const char *app_path);
int usage(int argc, char * const argv[]);

#ifdef __cplusplus
}
#endif

#endif // __CMD_LINE_PARSER_H__
