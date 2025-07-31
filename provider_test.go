package acme

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/libdns/libdns"
)

type testRecord struct {
	name string
	tp   string
	ttl  time.Duration
	data string
}

func (tr testRecord) RR() libdns.RR {
	return libdns.RR{
		Name: tr.name,
		Type: tr.tp,
		Data: tr.data,
		TTL:  tr.ttl,
	}
}

func TestProviderAppendRecords(t *testing.T) {
	provider := NewProvider()
	ctx := context.Background()
	var wg sync.WaitGroup
	type ZoneRecords struct {
		zoneName string
		records  []libdns.Record
	}
	zoneRecords := []ZoneRecords{}
	for i := 0; i < 3; i++ {
		zoneRecords = append(zoneRecords, ZoneRecords{
			zoneName: uuid.New().String(),
			records:  generateRandomRecords(5),
		})
	}
	wg.Add(len(zoneRecords))
	for _, zoneRecord := range zoneRecords {
		go func(zoneRecord ZoneRecords) {
			defer wg.Done()
			records, _ := provider.AppendRecords(ctx, zoneRecord.zoneName, zoneRecord.records)
			if len(zoneRecord.records) != len(records) {
				t.Errorf("provider.AppendRecords: expected %+v records but got %+v records", len(zoneRecord.records), len(records))
			}
			for i, rec := range zoneRecord.records {
				if !compareRecords(rec, records[i]) {
					t.Errorf("provider.AppendRecords: expected %+v but got %+v", rec, records[i])
				}
			}
		}(zoneRecord)
	}
	wg.Wait()
	for _, zoneRecord := range zoneRecords {
		records, err := provider.GetRecords(ctx, zoneRecord.zoneName)
		if err != nil {
			t.Errorf("provider.GetRecords: %s", err.Error())
		}
		if len(zoneRecord.records) != len(records) {
			t.Errorf("provider.AppendRecords: expected %+v records but got %+v records", len(zoneRecord.records), len(records))
		}
		for i, rec := range zoneRecord.records {
			if !compareRecords(rec, records[i]) {
				t.Errorf("provider.AppendRecords: expected %+v but got %+v", rec, records[i])
			}
		}
	}
}

func generateRandomRecords(n int) []libdns.Record {
	records := []libdns.Record{}
	for i := 0; i < n; i += 1 {
		records = append(records,
			testRecord{
				name: uuid.New().String(),
				tp:   uuid.New().String(),
				data: uuid.New().String(),
				ttl:  time.Minute,
			})
	}
	return records
}
