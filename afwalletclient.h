#ifndef __afwalletclient_h_
#define __afwalletclient_h_

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

char * ecdsa_keygen(const char *c_connstr, void(*cb)(int, void*), void *user_data, int *c_error);
char * get_master_address(const char *c_wallet_json, const char *network, int *c_error);
char * ecdsa_sign(const char *c_connstr, const char *c_wallet_str, const char *c_psbt_str, void(*cb)(int, void*), void *c_user_data, int *c_error);
 
#ifdef __cplusplus
}
#endif // __cplusplus
#endif // __afwalletclient_h_