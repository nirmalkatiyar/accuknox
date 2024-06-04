# eBPF TCP Packet Dropper

This project consists of an eBPF program and a Go program to drop TCP packets on a specified port. The default port is 4040, but it can be configured from userspace.

## Prerequisites

- Linux system with eBPF support
- `clang` and `llvm` installed
- `go` installed
- `iproute2` package (for `ip` and `tc` commands)
- `tcpdump` (for monitoring network traffic)


## Setup

1. **Download Necessary Headers:**

   Make sure you have the necessary BPF helper headers in the `headers` directory:

   ```sh
   mkdir -p headers/bpf
   wget https://raw.githubusercontent.com/torvalds/linux/master/tools/testing/selftests/bpf/bpf_helpers.h -O headers/bpf/bpf_helpers.h
   wget https://raw.githubusercontent.com/torvalds/linux/master/tools/testing/selftests/bpf/bpf_helper_defs.h -O headers/bpf/bpf_helper_defs.h
   wget https://raw.githubusercontent.com/torvalds/linux/master/tools/testing/selftests/bpf/bpf_tracing.h -O headers/bpf/bpf_tracing.h

2.  **Compile the BPF Program:**
    ```sh
    clang -O2 -target bpf -Iheaders -g -c drop_port.c -o drop_port.o



3. **Build the Go Program:**
    ```sh
    go build -o dropper main.go


## Run the Go Program:

1. **Execute the Go program with the desired port number as an argument:**
   ```sh
   sudo ./dropper <port>

2. **Generate Traffic:**
Generate TCP traffic to the specified port on the system where the BPF program is running. You can use tools like nc (netcat) or telnet.
    ```sh
   nc -vz <hostname or IP> 4040
   
3. **Verify Results:** 
    ```sh
    sudo tcpdump -i <interface> tcp port <port>
