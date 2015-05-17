#include "tls_api.h"
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/errno.h>
#include <netdb.h>

int
main(int argc, char *argv[])
{
    if (argc < 2)
    {
        fprintf(stderr, "Usage: %s <hostname> <port>\n",argv[0]);
        return(-1);
    }

    const char *hostname = argv[1];
    int port = 443;
    if (argc >= 3)
    {
        port = atoi(argv[2]);
    }

    fprintf(stderr, "[*] Resolving hostname (%s)\n", hostname);
    struct hostent *res =
    gethostbyname(hostname);

    if (res == NULL)
    {
        fprintf(stderr,"[E] Error looking up hostname (%s)\n", hostname);
        return (-1);
    }

    struct sockaddr_in addr;
    addr.sin_len            = sizeof(addr);
    addr.sin_family         = res->h_addrtype;
    addr.sin_port           = htons(port);
    addr.sin_addr           = *(struct in_addr *)(*res->h_addr_list);

    int s = socket(PF_INET, SOCK_STREAM, 0);
    if (s < 0)
    {
        fprintf(stderr, "[E] Error creating socket\n");
        return (-1);
    }

    fprintf(stderr, "[*] Connecting to ip (%s)....", inet_ntoa(addr.sin_addr));
    fflush(stderr);
    if (connect(s, (const struct sockaddr *)&addr, sizeof(addr)) != 0)
    {
        fprintf(stderr, "failed\n");
        return (-1);
    }
    fprintf(stderr, "done\n");

    mintls_session *session = mintls_create_client_session();

    unsigned char recv_buf[4096];

    for (;;)
    {
        size_t               to_write;
        unsigned char const* write_buf;

        enum mintls_error err = 
        mintls_pending_data(
            session,        // (I) Session
            &write_buf,     // (O) Pointer to data pending for transport layer
            &to_write       // (O) Number of bytes
        );
        if (err != mintls_success)
        {
            break;
        }
        if (to_write > 0)
        {
            ssize_t written = 0;
            while (written < to_write)
            {
                ssize_t m = to_write - written;
                /*
                fprintf(stderr, "[*] Writing %zu bytes:\n", m);
                unsigned i;
                fprintf(stderr, "       ");
                for (i = 0; i < m; ++i)
                {
                    fprintf(stderr, "%.2x ", write_buf[written+i]);
                    if (i % 32 == 31)
                    {
                        fprintf(stderr, "\n       ");
                    }
                }
                fprintf(stderr, "\n");
                */
                ssize_t n = send(s, write_buf + written, m, 0);
                if (n < 0)
                {
                    fprintf(stderr, "[E] Failed to write to socket\n");
                    return (-1);
                }
                written += n;
            }
        }

        unsigned char const * read_buf;
        size_t to_read;
        err =
        mintls_read_appdata(session, &read_buf, &to_read);
        if (err != mintls_success)
        {
            break;
        }

        while (to_read > 0)
        {
            ssize_t written = write(STDOUT_FILENO, read_buf, to_read);
            if (written < 0)
            {
                return (-1);
            }

            to_read -= written;
            read_buf += written;
        }

        fd_set rset;
        FD_ZERO(&rset);
        FD_SET(s, &rset);
        FD_SET(STDIN_FILENO, &rset);

        int activity = select(s + 1, &rset, NULL, NULL, NULL);

        if (activity < 0 && errno != EINTR)
        {
            fprintf(stderr, "[E] select error\n");
            return (-1);
        }
        if (FD_ISSET(s, &rset))
        {
            ssize_t read = recv(s, recv_buf, sizeof(recv_buf), 0);
            if (read == 0)
            {
                fprintf(stderr, "[E] connection closed\n");
                break;
            }
            else if (read < 0)
            {
                fprintf(stderr, "[E] recv error\n");
                break;
            }

            /*
            fprintf(stderr, "[*] Received %zu bytes\n", read);
            unsigned i;
            fprintf(stderr, "       ");
            for (i = 0; i < read; ++i)
            {
                fprintf(stderr, "%.2x ", recv_buf[i]);
                if (i % 32 == 31)
                {
                    fprintf(stderr, "\n       ");
                }
            }
            fprintf(stderr, "\n");
            */

            err =
            mintls_received_data(
                session,            // (I) Session
                recv_buf,           // (I) Received data
                (size_t)read        // (I) Number of bytes
            );
            if (err != mintls_success && err != mintls_pending)
            {
                fprintf(stderr,"[E] TLS Error: %s\n", mintls_error_string(err));
                break;
            }
        }
        if (FD_ISSET(STDIN_FILENO, &rset))
        {
            ssize_t sz = read(STDIN_FILENO, recv_buf, sizeof(recv_buf));
            if (sz == 0)
            {
                return 0;
            }
            err =
            mintls_write_appdata(
                session,    // (I) Session
                recv_buf,   // (I) Outgoing data for application layer
                sz          // (I) Number of bytes
            );
            if (err != mintls_success)
            {
                fprintf(stderr, "[E] Error writing data: %s\n", mintls_error_string(err));
            }
        }
    }

    mintls_destroy_session(session);

    return(0);
}
