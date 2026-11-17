// Licensed to Apache Software Foundation (ASF) under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Apache Software Foundation (ASF) licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package events

import (
	"bytes"
	"encoding/binary"
	"reflect"
	"testing"

	"github.com/apache/skywalking-rover/pkg/tools/btf"
	"github.com/apache/skywalking-rover/pkg/tools/buffer"
	"github.com/apache/skywalking-rover/pkg/tools/enums"
)

type testRecord struct {
	kind, direction    uint8
	cut                []byte
	start, end         uint64
	conid, randomID    uint64
	dataID, prevDataID uint64
	total, l4Size      uint64
	localPort, remote  uint16
	l4Count, funcName  uint8
	ssl                uint8
	inFlight           uint16
}

// buildBatch lays the records out as the BPF side does (bpf/accesslog/common/h2c_batch.h)
func buildBatch(records ...testRecord) []byte {
	b := make([]byte, batchHeaderSize+len(records)*BatchRecordSize)
	b[0] = BatchMarker
	binary.LittleEndian.PutUint32(b[batchCountOff:], uint32(len(records)))
	for i, r := range records {
		o := b[batchHeaderSize+i*BatchRecordSize:]
		o[recKind], o[recDirection], o[recCutLen] = r.kind, r.direction, uint8(len(r.cut))
		binary.LittleEndian.PutUint64(o[recStartTime:], r.start)
		binary.LittleEndian.PutUint64(o[recEndTime:], r.end)
		binary.LittleEndian.PutUint64(o[recConID:], r.conid)
		binary.LittleEndian.PutUint64(o[recRandomID:], r.randomID)
		binary.LittleEndian.PutUint64(o[recDataID:], r.dataID)
		binary.LittleEndian.PutUint64(o[recPrevDataID:], r.prevDataID)
		binary.LittleEndian.PutUint64(o[recTotalSize:], r.total)
		ext := o[recExt:]
		binary.LittleEndian.PutUint64(ext[extL4Size:], r.l4Size)
		binary.LittleEndian.PutUint16(ext[extLocalPort:], r.localPort)
		binary.LittleEndian.PutUint16(ext[extRemotePt:], r.remote)
		ext[extL4Count], ext[extFuncName], ext[extSSL] = r.l4Count, r.funcName, r.ssl
		binary.LittleEndian.PutUint16(ext[extInFlight:], r.inFlight)
		copy(o[recCutBuf:], r.cut)
	}
	return b
}

func TestBatchDecodeAndRefusedSample(t *testing.T) {
	header := []byte{0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05}
	sample := buildBatch(
		testRecord{kind: batchKindSkip, direction: 2, start: 10, end: 20, conid: 7, randomID: 9, dataID: 41,
			prevDataID: 40, total: 16384, l4Size: 16500, localPort: 8081, remote: 50000, l4Count: 12, funcName: 3, inFlight: 1},
		testRecord{kind: batchKindCut, direction: 1, cut: header, start: 30, end: 40, conid: 7, randomID: 9, dataID: 42,
			prevDataID: 41, total: 16393, l4Size: 16400, localPort: 8081, remote: 50000, l4Count: 11, funcName: 1, inFlight: 2},
	)
	if !IsBatchRecord(sample) || BatchRecordCount(sample) != 2 {
		t.Fatalf("batch not recognized")
	}
	for i := 0; i < 2; i++ {
		var fast SocketDataUploadEvent
		if !fast.DecodeBatchRecord(sample, i) {
			t.Fatalf("record %d did not decode", i)
		}
		// the refused-record sample must read back, through the normal decoder, as the same event
		var raw [UploadSampleSize]byte
		rawSample := BatchRecordAsUploadSample(sample, i, raw[:])
		var slow SocketDataUploadEvent
		slow.ReadFrom(btf.NewReader(rawSample))
		if fast.Protocol0 != enums.ConnectionProtocolHTTP2 || slow.Protocol0 != fast.Protocol0 ||
			slow.DataID0 != fast.DataID0 || slow.PrevDataID0 != fast.PrevDataID0 || slow.ConnectionID != fast.ConnectionID ||
			slow.RandomID != fast.RandomID || slow.TotalSize0 != fast.TotalSize0 || slow.StartTime0 != fast.StartTime0 ||
			slow.EndTime0 != fast.EndTime0 || slow.L4PackageCount != fast.L4PackageCount ||
			slow.L4TotalPackageSize != fast.L4TotalPackageSize || slow.FunctionName != fast.FunctionName ||
			slow.LocalPort != fast.LocalPort || slow.RemotePort != fast.RemotePort || slow.InFlight != fast.InFlight ||
			slow.Direction0 != fast.Direction0 || slow.PayloadSkipped0 != fast.PayloadSkipped0 ||
			slow.HaveReduce != fast.HaveReduce || slow.Finished != fast.Finished || slow.DataLen != fast.DataLen ||
			!bytes.Equal(slow.BufferData(), fast.BufferData()) {
			t.Fatalf("record %d: the refused sample reads back differently:\nfast %+v\nslow %+v", i, fast, slow)
		}
	}
	// the cut record keeps its bytes in the event itself, the skipped one has none
	var cut SocketDataUploadEvent
	cut.DecodeBatchRecord(sample, 1)
	if !bytes.Equal(cut.BufferData(), header) || cut.HaveReduce != 1 || cut.PayloadSkipped0 != 0 {
		t.Fatalf("cut record: %+v", cut)
	}
	if cut.ReleaseBuffer() != nil {
		t.Fatalf("a cut record must not hold a pooled buffer")
	}
	var skipped SocketDataUploadEvent
	skipped.DecodeBatchRecord(sample, 0)
	if skipped.PayloadSkipped0 != 1 || skipped.DataLen != 0 || skipped.Buffer != nil {
		t.Fatalf("skipped record: %+v", skipped)
	}
	// a 16-byte cut prefix (H2C_BATCH_CUT_MAX) must survive: the BPF read mask once turned 16 into 0
	full := bytes.Repeat([]byte{0xAB}, batchCutMax)
	big := buildBatch(testRecord{kind: batchKindCut, direction: 2, cut: full, dataID: 100, prevDataID: 99, total: 40000})
	var ev SocketDataUploadEvent
	if !ev.DecodeBatchRecord(big, 0) || ev.DataLen != uint16(batchCutMax) || !bytes.Equal(ev.BufferData(), full) {
		t.Fatalf("a 16-byte cut prefix did not round-trip: len=%d data=%v", ev.DataLen, ev.BufferData())
	}

	// a truncated sample is bounded by what it holds
	if BatchRecordCount(sample[:batchHeaderSize+BatchRecordSize]) != 1 {
		t.Fatalf("a truncated batch must report only the records it holds")
	}
}

// TestSplitH2CBatchRecords: the splitter delivers one compact record per admitted record, each its own
// allocation (and nothing else allocated but the cleanup of a sampled record), skips a record of an unknown kind
// with its admission given back, and reports a refused record as its raw event
func TestSplitH2CBatchRecords(t *testing.T) {
	recs := make([]testRecord, 0, 64)
	for i := 0; i < 64; i++ {
		r := testRecord{kind: batchKindSkip, direction: 1, conid: 3, randomID: 4, dataID: uint64(10 + i), prevDataID: uint64(9 + i), total: 100}
		if i%3 == 0 {
			r.kind, r.cut = batchKindCut, []byte{1, 2, 3}
		}
		recs = append(recs, r)
	}
	sample := buildBatch(recs...)
	release := func(data interface{}) { data.(*H2CRecord).Discard() }
	if allocs := testing.AllocsPerRun(100, func() { SplitH2CBatch(sample, release, nil) }); allocs > 64 {
		t.Fatalf("%.1f allocations for a batch of 64 records, expected one per record", allocs)
	}

	unknown := append([]testRecord{}, recs[:3]...)
	unknown[1].kind = 9
	sample = buildBatch(unknown...)
	inUse0, _, _, _ := buffer.MemoryStats() //nolint:dogsled // only the events in use are compared
	unknown0 := h2cUnknownRecords.Load()
	var got []*H2CRecord
	SplitH2CBatch(sample, func(data interface{}) { got = append(got, data.(*H2CRecord)) }, nil)
	if inUse, _, _, _ := buffer.MemoryStats(); len(got) != 2 || got[0].DataID0 != 10 || got[1].DataID0 != 12 || inUse-inUse0 != 2 {
		t.Fatalf("%d records, %d admissions held", len(got), inUse-inUse0)
	}
	if n := h2cUnknownRecords.Load() - unknown0; n != 1 {
		t.Fatalf("%d unknown records counted", n)
	}
	if got[0] == got[1] {
		t.Fatalf("the records of a batch share their memory")
	}
	for _, r := range got {
		r.Discard()
	}

	// every record refused: each one reported as its raw event, nothing delivered
	held := buffer.TakeBuffer(buffer.MaxEventBufferSize)
	defer buffer.ReleaseBufferOnly(held)
	buffer.SetMemoryBudget(1)
	defer buffer.SetMemoryBudget(0)
	var refused [][]byte
	delivered := 0
	SplitH2CBatch(buildBatch(recs[:4]...), func(interface{}) { delivered++ }, func(raw []byte) {
		refused = append(refused, append([]byte(nil), raw...))
	})
	if delivered != 0 || len(refused) != 4 {
		t.Fatalf("%d delivered, %d refused", delivered, len(refused))
	}
	var raw [UploadSampleSize]byte
	if want := BatchRecordAsUploadSample(buildBatch(recs[:4]...), 2, raw[:]); !bytes.Equal(refused[2], want) {
		t.Fatalf("refused sample %x, expected %x", refused[2], want)
	}
}

// TestDetachRecordLikeTheEvent: the detail copy of a record is the copy of the event the record decodes to
func TestDetachRecordLikeTheEvent(t *testing.T) {
	sample := buildBatch(
		testRecord{kind: batchKindSkip, direction: 2, start: 10, end: 20, conid: 7, randomID: 9, dataID: 41,
			prevDataID: 40, total: 16384, l4Size: 16500, localPort: 8081, remote: 50000, l4Count: 12, funcName: 3, inFlight: 1},
		testRecord{kind: batchKindCut, direction: 1, cut: bytes.Repeat([]byte{0xAB}, batchCutMax), start: 30, end: 40, conid: 7,
			randomID: 9, dataID: 42, prevDataID: 41, total: 16393, l4Size: 16400, localPort: 8081, remote: 50000, l4Count: 11,
			funcName: 1, inFlight: 2, ssl: 1},
	)
	var records []*H2CRecord
	SplitH2CBatch(sample, func(data interface{}) { records = append(records, data.(*H2CRecord)) }, nil)
	for i, r := range records {
		var e, fromEvent, fromRecord SocketDataUploadEvent
		if !e.DecodeBatchRecord(sample, i) {
			t.Fatal("decode")
		}
		e.DetachTo(&fromEvent)
		DetachRecordTo(r, &fromRecord)
		if !reflect.DeepEqual(fromEvent, fromRecord) || !DetachTo(r, &fromRecord) || !reflect.DeepEqual(fromEvent, fromRecord) {
			t.Fatalf("record %d: %+v, the event gives %+v", i, fromRecord, fromEvent)
		}
		r.Discard()
	}
}

// TestBatchRecordRun is a record that carries a run of whole DATA frames in front of it (sum_stream, sum_frames
// of the extension): the event, the compact record and the refused sample all read it back, the compact record
// behind its cut bytes
func TestBatchRecordRun(t *testing.T) {
	header := []byte{0x00, 0x40, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x05}
	sample := buildBatch(
		testRecord{kind: batchKindCut, direction: 2, cut: header, conid: 7, randomID: 9, dataID: 42, prevDataID: 41,
			total: 16393},
		testRecord{kind: batchKindSkip, direction: 2, conid: 7, randomID: 9, dataID: 43, prevDataID: 42, total: 100},
		testRecord{kind: batchKindCut, direction: 2, cut: bytes.Repeat([]byte{1}, 11), conid: 7, randomID: 9, dataID: 44,
			prevDataID: 43, total: 16400},
	)
	runs := []struct {
		before, stream uint32
		frames         uint16
	}{{16393 * 15, 0x7ffffffd, 15}, {200, 3, 1}, {16393, 5, 1}}
	for i, r := range runs {
		ext := sample[batchHeaderSize+i*BatchRecordSize+recExt:]
		ext[extH2CFrames] = uint8(1 + i%2*2)
		binary.LittleEndian.PutUint16(ext[extFirstFrame:], uint16(i*3))
		binary.LittleEndian.PutUint32(ext[extSumBefore:], r.before)
		binary.LittleEndian.PutUint32(ext[extSumStream:], r.stream)
		binary.LittleEndian.PutUint16(ext[extSumFrames:], r.frames)
	}
	for i, r := range runs {
		var e SocketDataUploadEvent
		if !e.DecodeBatchRecord(sample, i) || e.SumBefore != r.before || e.SumStream != r.stream || e.SumFrames != r.frames {
			t.Fatalf("record %d as an event: %+v", i, e)
		}
		var raw [UploadSampleSize]byte
		var slow SocketDataUploadEvent
		slow.ReadFrom(btf.NewReader(BatchRecordAsUploadSample(sample, i, raw[:])))
		if slow.H2CFrames0 != e.H2CFrames0 || slow.FirstFrameOff != e.FirstFrameOff || e.H2CFrames0 != uint8(1+i%2*2) ||
			e.FirstFrameOff != uint16(i*3) {
			t.Fatalf("record %d: the frames %d/%d, %d/%d", i, e.H2CFrames0, e.FirstFrameOff, slow.H2CFrames0, slow.FirstFrameOff)
		}
		if slow.SumBefore != r.before || slow.SumStream != r.stream || slow.SumFrames != r.frames {
			t.Fatalf("record %d as a refused sample: %+v", i, slow)
		}
		var c SocketDataUploadEvent
		rec := buffer.NewCompactRecord()
		ok := decodeRecord(rec, sample, i)
		if i == 2 {
			// 11 cut bytes leave no room for the run (BPF sends no such record): not a compact record
			if ok {
				t.Fatalf("record %d with 11 cut bytes and a run decoded as a compact record", i)
			}
			continue
		}
		if flags, off := rec.H2CFrames(); flags != e.H2CFrames0 || off != e.FirstFrameOff {
			t.Fatalf("record %d as a compact record: the frames %d/%d", i, flags, off)
		}
		stream, frames := rec.SummaryRun()
		DetachRecordTo(rec, &c)
		if !ok || rec.SummarizedBefore() != r.before || stream != r.stream || frames != r.frames ||
			c.SumStream != r.stream || c.SumFrames != r.frames || !bytes.Equal(rec.BufferData(), e.BufferData()) {
			t.Fatalf("record %d as a compact record: %v %d %d %d %+v", i, ok, rec.SummarizedBefore(), stream, frames, c)
		}
	}
	// the splitter hands the record it cannot keep over as the event
	var got []interface{}
	SplitH2CBatch(sample, func(data interface{}) { got = append(got, data) }, func([]byte) {})
	if len(got) != 3 {
		t.Fatalf("%d delivered", len(got))
	}
	if e, ok := got[2].(*SocketDataUploadEvent); !ok || e.SumStream != 5 || e.DataLen != 11 {
		t.Fatalf("the third record was delivered as %T %+v", got[2], got[2])
	}
	for _, d := range got[:2] {
		if _, ok := d.(*H2CRecord); !ok {
			t.Fatalf("delivered %T", d)
		}
	}
}
