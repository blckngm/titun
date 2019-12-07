/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2019 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"C"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"unsafe"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"

	"golang.zx2c4.com/wireguard/tun"
)

const (
	ExitSetupSuccess = 0
	ExitSetupFailed  = 1
)

// To build the dll, use:
// go build -o wintun.dll -buildmode=c-shared main_windows.go

//export WintunOpen
func WintunOpen(name *C.char, name_len C.int) unsafe.Pointer {
	name1 := C.GoStringN(name, name_len)

	// Does an interface with this name already exist?
	wt, err := tun.WintunPool.GetInterface(name1)
	if err == nil {
		// If so, we delete it, in case it has weird residual configuration.
		_, err = wt.DeleteInterface()
		if err != nil {
			fmt.Fprintln(os.Stderr, "WintunOpen: DeleteInterface:", err)
			return nil
		}
	}

	wt, rebootRequired, err := tun.WintunPool.CreateInterface(name1, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "WintunOpen: CreateInterface:", err)
		return nil
	}
	if rebootRequired {
		fmt.Fprintln(os.Stderr, "WintunOpen: reboot required")
	}

	handle, err := wt.Handle()
	if err != nil {
		fmt.Fprintln(os.Stderr, "WintunOpen: Handle:", err)
		return nil
	}

	return unsafe.Pointer(handle)
}

//export WintunClose
func WintunClose(name *C.char, name_len C.int) {
	name1 := C.GoStringN(name, name_len)

	wt, err := tun.WintunPool.GetInterface(name1)
	if err != nil {
		fmt.Fprintln(os.Stderr, "WintunClose: GetInterface:", err)
		return
	}
	_, err = wt.DeleteInterface()
	if err != nil {
		fmt.Fprintln(os.Stderr, "WintunClose: DeleteInterface:", err)
	}
}

func main() {
	if len(os.Args) != 2 {
		os.Exit(ExitSetupFailed)
	}
	interfaceName := os.Args[1]

	fmt.Fprintln(os.Stderr, "Warning: this is a test program for Windows, mainly used for debugging this Go package. For a real WireGuard for Windows client, the repo you want is <https://git.zx2c4.com/wireguard-windows/>, which includes this code as a module.")

	logger := device.NewLogger(
		device.LogLevelDebug,
		fmt.Sprintf("(%s) ", interfaceName),
	)
	logger.Info.Println("Starting wireguard-go version", device.WireGuardGoVersion)
	logger.Debug.Println("Debug log enabled")

	tun, err := tun.CreateTUN(interfaceName, 0)
	if err == nil {
		realInterfaceName, err2 := tun.Name()
		if err2 == nil {
			interfaceName = realInterfaceName
		}
	} else {
		logger.Error.Println("Failed to create TUN device:", err)
		os.Exit(ExitSetupFailed)
	}

	device := device.NewDevice(tun, logger)
	device.Up()
	logger.Info.Println("Device started")

	uapi, err := ipc.UAPIListen(interfaceName)
	if err != nil {
		logger.Error.Println("Failed to listen on uapi socket:", err)
		os.Exit(ExitSetupFailed)
	}

	errs := make(chan error)
	term := make(chan os.Signal, 1)

	go func() {
		for {
			conn, err := uapi.Accept()
			if err != nil {
				errs <- err
				return
			}
			go device.IpcHandle(conn)
		}
	}()
	logger.Info.Println("UAPI listener started")

	// wait for program to terminate

	signal.Notify(term, os.Interrupt)
	signal.Notify(term, os.Kill)
	signal.Notify(term, syscall.SIGTERM)

	select {
	case <-term:
	case <-errs:
	case <-device.Wait():
	}

	// clean up

	uapi.Close()
	device.Close()

	logger.Info.Println("Shutting down")
}
