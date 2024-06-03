package main

import (
    "encoding/binary"
    "fmt"
    "os"
    "os/signal"
    "strconv"
    "syscall"

    "github.com/cilium/ebpf"
    "github.com/cilium/ebpf/rlimit"
    "github.com/vishvananda/netlink"
)

func main() {
    if len(os.Args) != 2 {
        fmt.Fprintf(os.Stderr, "Usage: %s <port>\n", os.Args[0])
        os.Exit(1)
    }

    port, err := strconv.Atoi(os.Args[1])
    if err != nil {
        fmt.Fprintf(os.Stderr, "Invalid port: %v\n", err)
        os.Exit(1)
    }

    if port < 1 || port > 65535 {
        fmt.Fprintf(os.Stderr, "Port number out of range: %d\n", port)
        os.Exit(1)
    }

    // Allow the current process to lock memory for eBPF resources.
    if err := rlimit.RemoveMemlock(); err != nil {
        fmt.Fprintf(os.Stderr, "Failed to remove memlock: %v\n", err)
        os.Exit(1)
    }

    // Load the compiled BPF program
    spec, err := ebpf.LoadCollectionSpec("drop_port.o")
    if err != nil {
        fmt.Fprintf(os.Stderr, "Failed to load BPF program: %v\n", err)
        os.Exit(1)
    }

    collection, err := ebpf.NewCollection(spec)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Failed to create BPF collection: %v\n", err)
        os.Exit(1)
    }
    defer collection.Close()

    prog := collection.DetachProgram("xdp_drop_tcp_port")
    if prog == nil {
        fmt.Fprintf(os.Stderr, "Failed to find BPF program\n")
        os.Exit(1)
    }
    defer prog.Close()

    dropPortMap := collection.DetachMap("drop_port_map")
    if dropPortMap == nil {
        fmt.Fprintf(os.Stderr, "Failed to find BPF map\n")
        os.Exit(1)
    }
    defer dropPortMap.Close()

    // Attach the program to a network interface
    iface, err := netlink.LinkByName("enp0s3")
    if err != nil {
        fmt.Fprintf(os.Stderr, "Failed to find interface: %v\n", err)
        os.Exit(1)
    }

    if err := netlink.LinkSetXdpFd(iface, prog.FD()); err != nil {
        fmt.Fprintf(os.Stderr, "Failed to attach BPF program: %v\n", err)
        os.Exit(1)
    }

    // Convert the port to network byte order.
    portBytes := make([]byte, 2)
    binary.BigEndian.PutUint16(portBytes, uint16(port))

    key := uint32(0)

    // Update the map with the new port.
    if err := dropPortMap.Update(&key, portBytes, ebpf.UpdateAny); err != nil {
        fmt.Fprintf(os.Stderr, "Failed to update BPF map: %v\n", err)
        os.Exit(1)
    }

    fmt.Printf("Set drop port to %d\n", port)

    // Wait for an interrupt signal to detach the BPF program and clean up
    sig := make(chan os.Signal, 1)
    signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
    <-sig

    // Clean up
    if err := netlink.LinkSetXdpFd(iface, -1); err != nil {
        fmt.Fprintf(os.Stderr, "Failed to detach BPF program: %v\n", err)
    }
}
