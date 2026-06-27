package stream

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"time"
)

// Publisher is a minimal Hermes producer client.
// It speaks Hermes's binary protocol directly over TCP.
// Frame format: [4-byte topic length][topic bytes][4-byte payload length][payload bytes]
type Publisher struct {
	brokerAddr string
	topic      string
	conn       net.Conn
}

// NewPublisher dials the Hermes broker and returns a ready Publisher.
func NewPublisher(brokerAddr, topic string) (*Publisher, error) {
	conn, err := net.DialTimeout("tcp", brokerAddr, 3*time.Second)
	if err != nil {
		return nil, fmt.Errorf("connect to hermes broker: %w", err)
	}
	return &Publisher{brokerAddr: brokerAddr, topic: topic, conn: conn}, nil
}

// Publish serialises event as JSON and sends it using Hermes's binary frame format.
// key is used for partition routing (typically the transaction ID).
func (p *Publisher) Publish(ctx context.Context, key string, event any) error {
	payload, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}

	frame := encodeProduceRequest(p.topic, key, payload)
	if _, err := p.conn.Write(frame); err != nil {
		return fmt.Errorf("hermes publish: %w", err)
	}
	return nil
}

// Close releases the TCP connection.
func (p *Publisher) Close() error {
	return p.conn.Close()
}

// encodeProduceRequest builds the Hermes binary ProduceRequest frame.
// Layout: [4B topic-len][topic][4B key-len][key][4B payload-len][payload]
func encodeProduceRequest(topic, key string, payload []byte) []byte {
	topicBytes := []byte(topic)
	keyBytes := []byte(key)

	size := 4 + len(topicBytes) + 4 + len(keyBytes) + 4 + len(payload)
	buf := make([]byte, size)
	offset := 0

	binary.BigEndian.PutUint32(buf[offset:], uint32(len(topicBytes)))
	offset += 4
	copy(buf[offset:], topicBytes)
	offset += len(topicBytes)

	binary.BigEndian.PutUint32(buf[offset:], uint32(len(keyBytes)))
	offset += 4
	copy(buf[offset:], keyBytes)
	offset += len(keyBytes)

	binary.BigEndian.PutUint32(buf[offset:], uint32(len(payload)))
	offset += 4
	copy(buf[offset:], payload)

	return buf
}
