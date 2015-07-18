/***** BEGIN LICENSE BLOCK *****
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
#
# The Initial Developer of the Original Code is the Mozilla Foundation.
# Portions created by the Initial Developer are Copyright (C) 2012-2014
# the Initial Developer. All Rights Reserved.
#
# Contributor(s):
#   Rob Miller (rmiller@mozilla.com)
#   Mike Trinkala (trink@mozilla.com)
#   Carlos Diaz-Padron (cpadron@mozilla.com,carlos@carlosdp.io)
#
# ***** END LICENSE BLOCK *****/

package tcp

import (
	"crypto/tls"
	"fmt"
	"net"
	"regexp"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mozilla-services/heka/message"
	. "github.com/mozilla-services/heka/pipeline"
)

// Output plugin that sends messages via TCP using the Heka protocol.
type TcpOutput struct {
	processMessageCount int64
	dropMessageCount    int64
	activeServer        int64
	serverTimeout       []time.Time
	keepAliveDuration   time.Duration
	conf                *TcpOutputConfig
	addresses           []string
	localAddress        net.Addr
	connections         []net.Conn
	name                string
	reportLock          sync.Mutex
	bufferedOut         *BufferedOutput
	or                  OutputRunner
	outputBlock         *RetryHelper
	pConfig             *PipelineConfig
}

// ConfigStruct for TcpOutput plugin.
type TcpOutputConfig struct {
	// String representation of the TCP address to which this output should be
	// sending data.
	Addresses    []string
	LocalAddress string `toml:"local_address"`
	UseTls       bool   `toml:"use_tls"`
	Tls          TlsConfig
	// Interval at which the output queue logs will roll, in seconds. Defaults
	// to 300.
	TickerInterval uint `toml:"ticker_interval"`
	// Allows for a default encoder.
	Encoder string
	// Set to true if TCP Keep Alive should be used.
	KeepAlive bool `toml:"keep_alive"`
	// Integer indicating seconds between keep alives.
	KeepAlivePeriod int `toml:"keep_alive_period"`
	// Specifies whether or not Heka's stream framing wil be applied to the
	// output. We do some magic to default to true if ProtobufEncoder is used,
	// false otherwise.
	UseFraming *bool `toml:"use_framing"`
	// Specifies size of queue buffer for output. 0 means that buffer is
	// unlimited.
	QueueMaxBufferSize uint64 `toml:"queue_max_buffer_size"`
	// Specifies action which should be executed if queue is full. Possible
	// values are "shutdown", "drop", or "block".
	QueueFullAction string `toml:"queue_full_action"`
}

func (t *TcpOutput) ConfigStruct() interface{} {
	return &TcpOutputConfig{
		Addresses:          []string{"localhost:9125"},
		TickerInterval:     uint(300),
		Encoder:            "ProtobufEncoder",
		QueueMaxBufferSize: 0,
		QueueFullAction:    "shutdown",
	}
}

func (t *TcpOutput) SetName(name string) {
	re := regexp.MustCompile("\\W")
	t.name = re.ReplaceAllString(name, "_")
}

func (t *TcpOutput) Init(config interface{}) (err error) {
	t.conf = config.(*TcpOutputConfig)
	t.addresses = t.conf.Addresses
	t.connections = make([]net.Conn, len(t.addresses))
	t.serverTimeout = make([]time.Time, len(t.addresses))

	if t.conf.LocalAddress != "" {
		// Error out if use_tls and local_address options are both set for now.
		if t.conf.UseTls {
			return fmt.Errorf("Cannot combine local_address %s and use_tls config options",
				t.localAddress)
		}
		t.localAddress, err = net.ResolveTCPAddr("tcp", t.conf.LocalAddress)
	}

	if t.conf.KeepAlivePeriod != 0 {
		t.keepAliveDuration = time.Duration(t.conf.KeepAlivePeriod) * time.Second
	}

	switch t.conf.QueueFullAction {
	case "shutdown", "drop", "block":
	default:
		return fmt.Errorf("`queue_full_action` must be 'shutdown', 'drop', or 'block', got %s",
			t.conf.QueueFullAction)
	}
	return
}

func (t *TcpOutput) connect(i int) (err error) {
	dialer := &net.Dialer{LocalAddr: t.localAddress}

	if t.conf.UseTls {
		var goTlsConf *tls.Config
		if goTlsConf, err = CreateGoTlsConfig(&t.conf.Tls); err != nil {
			return fmt.Errorf("TLS init error: %s", err)
		}
		t.connections[i], err = tls.DialWithDialer(dialer, "tcp", t.addresses[i], goTlsConf)
	} else {
		t.connections[i], err = dialer.Dial("tcp", t.addresses[i])
	}
	if t.connections[i] != nil && t.conf.KeepAlive {
		tcpConn, ok := t.connections[i].(*net.TCPConn)
		if !ok {
			t.or.LogError(fmt.Errorf("KeepAlive only supported for TCP Connections."))
		} else {
			tcpConn.SetKeepAlive(t.conf.KeepAlive)
			if t.keepAliveDuration != 0 {
				tcpConn.SetKeepAlivePeriod(t.keepAliveDuration)
			}
		}
	}
	return
}

func (t *TcpOutput) SendRecord(record []byte) (err error) {
	defer func() {
		t.activeServer++
	}()

	var n int
	for attempt := range t.addresses {
		i := int((t.activeServer + int64(attempt)) % int64(len(t.addresses)))
		if err != nil {
			// Print the last error since it won't be returned
			t.or.LogError(err)
		}

		if t.connections[i] == nil {
			if attempt == len(t.addresses)-1 || t.serverTimeout[i].Before(time.Now()) {
				if err = t.connect(i); err != nil {
					// Explicitly set t.connections[i] to nil because Go, see
					// http://golang.org/doc/faq#nil_error.
					t.connections[i] = nil
					t.serverTimeout[i] = time.Now().Add(30 * time.Second)
					return
				}
			} else {
				continue
			}
		}

		cleanupConn := func() {
			if t.connections[i] != nil {
				t.connections[i].Close()
				t.connections[i] = nil
				t.serverTimeout[i] = time.Now().Add(30 * time.Second)
			}
		}

		if n, err = t.connections[i].Write(record); err != nil {
			cleanupConn()
			err = fmt.Errorf("writing to %s: %s", t.addresses[i], err)
		} else if n != len(record) {
			cleanupConn()
			err = fmt.Errorf("truncated output to: %s", t.addresses[i])
			return
		}
		if err == nil {
			return
		}
	}
	return
}

func (t *TcpOutput) Run(or OutputRunner, h PluginHelper) (err error) {
	var (
		ok          = true
		pack        *PipelinePack
		inChan      = or.InChan()
		ticker      = or.Ticker()
		outputExit  = make(chan error)
		outputError = make(chan error, 5)
		stopChan    = make(chan bool, 1)
	)

	t.outputBlock, err = NewRetryHelper(RetryOptions{
		MaxDelay:   "5s",
		MaxRetries: -1,
	})
	if err != nil {
		return fmt.Errorf("can't create retry helper: %s", err.Error())
	}

	t.pConfig = h.PipelineConfig()

	if t.conf.UseFraming == nil {
		// Nothing was specified, we'll default to framing IFF ProtobufEncoder
		// is being used.
		if _, ok := or.Encoder().(*ProtobufEncoder); ok {
			or.SetUseFraming(true)
		}
	}
	t.or = or

	defer func() {
		for i := range t.connections {
			if t.connections[i] != nil {
				t.connections[i].Close()
				t.connections[i] = nil
			}
		}
	}()

	t.bufferedOut, err = NewBufferedOutput("output_queue", t.name, or, h,
		t.conf.QueueMaxBufferSize)
	if err != nil {
		if err == QueueIsFull {
			or.LogMessage("Queue capacity is already reached.")
		} else {
			return
		}
	}
	t.bufferedOut.Start(t, outputError, outputExit, stopChan)

	dupFullMsg := false // Prevents log from overflowing w/ dup queue full msgs
	for ok {
		select {
		case e := <-outputError:
			or.LogError(e)

		case pack, ok = <-inChan:
			if !ok {
				stopChan <- true
				<-outputExit

				break
			}
			if err := t.bufferedOut.QueueRecord(pack); err != nil {
				if err == QueueIsFull {
					if !dupFullMsg {
						or.LogError(err)
						dupFullMsg = true
					}
					ok = t.queueFull(pack)
				} else {
					or.LogError(err)
					dupFullMsg = false
				}
			} else {
				atomic.AddInt64(&t.processMessageCount, 1)
				dupFullMsg = false
			}
			pack.Recycle()

		case <-ticker:
			if err = t.bufferedOut.RollQueue(); err != nil {
				return fmt.Errorf("can't create new buffer queue file: %s", err.Error())
			}

		case err = <-outputExit:
			ok = false
		}
	}

	return
}

// This function will be called if the queue is full and another item is sent
// to the queue. The result depends on the configured queue full action.
// The returned bool indicates if the queue can continue to accept items.
func (t *TcpOutput) queueFull(pack *PipelinePack) bool {
	switch t.conf.QueueFullAction {
	// Tries to queue message until its possible to send it to output.
	case "block":
		for t.outputBlock.Wait() == nil {
			if t.pConfig.Globals.IsShuttingDown() {
				return false
			}
			blockErr := t.bufferedOut.QueueRecord(pack)
			if blockErr == nil {
				atomic.AddInt64(&t.processMessageCount, 1)
				break
			}
			runtime.Gosched()
		}
	// Terminate Heka activity.
	case "shutdown":
		t.pConfig.Globals.ShutDown()
		return false

	// Drop packets
	case "drop":
		atomic.AddInt64(&t.dropMessageCount, 1)
	}
	return true
}

func init() {
	RegisterPlugin("TcpOutput", func() interface{} {
		return new(TcpOutput)
	})
}

// Satisfies the `pipeline.ReportingPlugin` interface to provide plugin state
// information to the Heka report and dashboard.
func (t *TcpOutput) ReportMsg(msg *message.Message) error {
	t.reportLock.Lock()
	defer t.reportLock.Unlock()

	message.NewInt64Field(msg, "ProcessMessageCount",
		atomic.LoadInt64(&t.processMessageCount), "count")
	message.NewInt64Field(msg, "DropMessageCount",
		atomic.LoadInt64(&t.dropMessageCount), "count")

	t.bufferedOut.ReportMsg(msg)
	return nil
}
