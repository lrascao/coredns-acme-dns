package acme

import (
	"context"
	"fmt"
	"sync"

	"github.com/libdns/libdns"
)

var (
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
)

type recordStore struct {
	entries []libdns.Record
}

type Provider struct {
	sync.Mutex
	recordMap map[string]*recordStore
}

func NewProvider() *Provider {
	return &Provider{
		recordMap: make(map[string]*recordStore),
	}
}

func (p *Provider) AppendRecords(ctx context.Context, zoneName string, recs []libdns.Record) ([]libdns.Record, error) {
	p.Lock()
	defer p.Unlock()
	zoneRecordStore := p.getZoneRecords(ctx, zoneName)
	if zoneRecordStore == nil {
		zoneRecordStore = new(recordStore)
		p.recordMap[zoneName] = zoneRecordStore
	}
	zoneRecordStore.entries = append(zoneRecordStore.entries, recs...)
	return zoneRecordStore.entries, nil
}

func (p *Provider) DeleteRecords(ctx context.Context, zoneName string, recs []libdns.Record) ([]libdns.Record, error) {
	p.Lock()
	defer p.Unlock()
	zoneRecordStore := p.getZoneRecords(ctx, zoneName)
	if zoneRecordStore == nil {
		return nil, nil
	}
	deletedRecords := zoneRecordStore.deleteRecords(recs)
	return deletedRecords, nil
}

func (p *Provider) GetRecords(ctx context.Context, zoneName string) ([]libdns.Record, error) {
	p.Lock()
	defer p.Unlock()
	zoneRecordStore := p.getZoneRecords(ctx, zoneName)
	if zoneRecordStore == nil {
		return nil, fmt.Errorf("no records were found for %v", zoneName)
	}
	return zoneRecordStore.entries, nil
}

func (p *Provider) getZoneRecords(ctx context.Context, zoneName string) *recordStore {
	records, found := p.recordMap[zoneName]
	if !found {
		return nil
	}
	return records
}

func compareRecords(a, b libdns.Record) bool {
	return a.RR().Type == b.RR().Type &&
		a.RR().Name == b.RR().Name &&
		a.RR().Data == b.RR().Data &&
		a.RR().TTL == b.RR().TTL
}

func (r *recordStore) deleteRecords(recs []libdns.Record) []libdns.Record {
	deletedRecords := []libdns.Record{}
	for i, entry := range r.entries {
		for _, record := range recs {
			if compareRecords(entry, record) {
				deletedRecords = append(deletedRecords, record)
				r.entries = append(r.entries[:i], r.entries[i+1:]...)
			}
		}
	}
	return deletedRecords
}
