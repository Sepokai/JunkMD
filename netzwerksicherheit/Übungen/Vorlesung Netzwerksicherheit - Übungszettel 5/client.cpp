#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>

int connect(int port)
{
	int s;
	struct sockaddr_in addr;

	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = inet_addr("127.0.0.1");

	s = socket(AF_INET, SOCK_STREAM, 0);
	if (s < 0) {
		perror("Unable to create socket");
		exit(EXIT_FAILURE);
	}

	connect(s, (struct sockaddr *) &addr, sizeof(addr) );
	return s;
}

void init_openssl()
{ 
	SSL_load_error_strings(); 
	OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl()
{
	EVP_cleanup();
}

int verify_callback(int preverify_ok, X509_STORE_CTX *ctx)
{
	return 1;
}

SSL_CTX *create_context()
{
	const SSL_METHOD *method;
	SSL_CTX *ctx;

	method = TLS_client_method();;

	ctx = SSL_CTX_new(method);
	if (!ctx) {
		perror("Unable to create SSL context");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	return ctx;
}

void configure_context(SSL_CTX *ctx)
{
	SSL_CTX_set_ecdh_auto(ctx, 1);

	/* Set the key and cert */
	if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	if (SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0 ) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER|SSL_VERIFY_CLIENT_ONCE, verify_callback);
}

void hex_encode(unsigned char* readbuf, void *writebuf, size_t len)
{
	for(size_t i=0; i < len; i++) {
		char *l = (char*) (2*i + ((intptr_t) writebuf));
		sprintf(l, "%02x", readbuf[i]);
	}
}

void calc_digest(SSL *ssl, X509 *cert)
{
	#define DIGEST_LENGTH 32
	char buf[DIGEST_LENGTH];

	const EVP_MD *digest = EVP_sha256();
	unsigned len;

	int rc = X509_digest(cert, digest, (unsigned char*) buf, &len);
	if (rc == 1 || len != DIGEST_LENGTH) {
		char strbuf[2*DIGEST_LENGTH+1];
		memset(strbuf, '\0', 2*DIGEST_LENGTH+1);
		hex_encode((unsigned char*)buf, strbuf, DIGEST_LENGTH);
		fprintf(stderr, "Server FP: %s\n", strbuf);
  	SSL_write(ssl, strbuf, strlen(strbuf));
		return;
	}
	fprintf(stderr, "No Fingerprint for certificate found");
	return;
}

int main(int argc, char **argv)
{
	int sock;
	SSL_CTX *ctx;
	SSL_library_init();

	init_openssl();
	ctx = create_context();

	configure_context(ctx);

	sock = connect(4433);

		SSL *ssl;

		ssl = SSL_new(ctx);
		SSL_set_fd(ssl, sock);
		if ( SSL_connect(ssl) <= 0 ){
			printf("Error in SSL connect\n");
			ERR_print_errors_fp(stderr);
		} else {
			fprintf(stderr, "Connected\n");
			X509* cert = SSL_get_peer_certificate(ssl);
			if(cert) {
				X509_NAME* name = X509_get_subject_name(cert);
				char *cname = X509_NAME_oneline(name, NULL, 0);
				fprintf(stderr, "Cert name: %s\n", (char*) cname);
				calc_digest(ssl, cert);
			}
			X509_free(cert);
		}

		char buf[65];
		memset(buf, '\0', 65);
		int bytes = SSL_read(ssl, buf, sizeof(buf)); /* get reply & decrypt */
		printf("%s\n", buf);

		SSL_shutdown(ssl);
		SSL_free(ssl);
	close(sock);
	SSL_CTX_free(ctx);
	cleanup_openssl();
}
