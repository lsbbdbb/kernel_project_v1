import socket
import select
import threading
import sys
from paramiko import SSHClient, AutoAddPolicy

def handler(client_sock, remote_host, remote_port, transport):
    try:
        channel = transport.open_channel(
            "direct-tcpip", (remote_host, remote_port), client_sock.getpeername()
        )
        if channel is None:
            client_sock.close()
            return
        while True:
            r, w, x = select.select([client_sock, channel], [], [])
            if client_sock in r:
                data = client_sock.recv(4096)
                if len(data) == 0:
                    break
                channel.send(data)
            if channel in r:
                data = channel.recv(4096)
                if len(data) == 0:
                    break
                client_sock.send(data)
    except Exception as e:
        print(f"[handler error] {e}")
    finally:
        try:
            client_sock.close()
        except:
            pass
        try:
            channel.close()
        except:
            pass

def main():
    local_port = 8080
    remote_host = "127.0.0.1"
    remote_port = 8080
    ssh_host = "100.64.162.82"
    ssh_user = "lee"
    ssh_pass = "040102"

    client = SSHClient()
    client.set_missing_host_key_policy(AutoAddPolicy())
    client.connect(ssh_host, username=ssh_user, password=ssh_pass, look_for_keys=False)

    transport = client.get_transport()
    transport.request_port_forward("", local_port)

    print(f"[tunnel] localhost:{local_port} -> {ssh_host}:{remote_port}")

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", local_port))
    server.listen(5)
    print("[tunnel] waiting for connections... (Ctrl+C to stop)")

    try:
        while True:
            client_sock, addr = server.accept()
            print(f"[tunnel] connection from {addr}")
            t = threading.Thread(target=handler, args=(client_sock, remote_host, remote_port, transport))
            t.daemon = True
            t.start()
    except KeyboardInterrupt:
        print("\n[tunnel] shutting down")
    finally:
        server.close()
        client.close()

if __name__ == "__main__":
    main()
