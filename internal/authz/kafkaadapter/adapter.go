package kafkaadapter

import (
	"context"
	"errors"

	"authz-system/internal/authz"

	"github.com/segmentio/kafka-go"
)

const (
	BrokerNameKafka       = "kafka"
	HeaderServiceName     = "X-Service-Name"
	HeaderMessageType     = "X-Message-Type"
	DefaultTargetService  = "payments"
	DefaultRequestedTopic = "payments.requested"
)

var (
	ErrMissingServiceName = errors.New("kafka message missing X-Service-Name header")
	ErrMissingMessageType = errors.New("kafka message missing X-Message-Type header")
	ErrMissingTopic       = errors.New("kafka message topic is empty")
)

type Adapter struct {
	targetService string
	broker        authz.BrokerAuthzAdapter
}

func New(cfg authz.Config) (*Adapter, error) {
	broker, err := authz.NewGenericBrokerAdapter(cfg)
	if err != nil {
		return nil, err
	}
	target := cfg.TargetService
	if target == "" {
		target = DefaultTargetService
	}
	return &Adapter{targetService: target, broker: broker}, nil
}

func NewWithBrokerAuthzAdapter(targetService string, broker authz.BrokerAuthzAdapter) *Adapter {
	if targetService == "" {
		targetService = DefaultTargetService
	}
	return &Adapter{targetService: targetService, broker: broker}
}

func (a *Adapter) Publish(ctx context.Context, writer *kafka.Writer, msg kafka.Message, sourceService, messageType string) error {
	topic := topicForMessage(writer, msg)
	if topic == "" {
		return ErrMissingTopic
	}

	interaction := authz.BrokerInteraction{
		SourceService: sourceService,
		TargetService: a.targetService,
		Broker:        BrokerNameKafka,
		Resource:      topic,
		MessageType:   messageType,
	}
	if _, err := a.broker.AuthorizePublish(ctx, interaction); err != nil {
		return err
	}

	if writer == nil || writer.Topic == "" {
		msg.Topic = topic
	} else {
		msg.Topic = ""
	}
	msg.Headers = upsertHeader(msg.Headers, HeaderServiceName, sourceService)
	msg.Headers = upsertHeader(msg.Headers, HeaderMessageType, messageType)
	return writer.WriteMessages(ctx, msg)
}

func (a *Adapter) AuthorizeConsume(ctx context.Context, msg kafka.Message) error {
	topic := msg.Topic
	if topic == "" {
		return ErrMissingTopic
	}
	sourceService, err := ServiceNameFromHeaders(msg.Headers)
	if err != nil {
		return err
	}
	messageType, err := MessageTypeFromHeaders(msg.Headers)
	if err != nil {
		return err
	}

	interaction := authz.BrokerInteraction{
		SourceService: sourceService,
		TargetService: a.targetService,
		Broker:        BrokerNameKafka,
		Resource:      topic,
		MessageType:   messageType,
	}
	_, err = a.broker.AuthorizeConsume(ctx, interaction)
	return err
}

func ServiceNameFromHeaders(headers []kafka.Header) (string, error) {
	v := headerValue(headers, HeaderServiceName)
	if v == "" {
		return "", ErrMissingServiceName
	}
	return v, nil
}

func MessageTypeFromHeaders(headers []kafka.Header) (string, error) {
	v := headerValue(headers, HeaderMessageType)
	if v == "" {
		return "", ErrMissingMessageType
	}
	return v, nil
}

func upsertHeader(headers []kafka.Header, key, value string) []kafka.Header {
	for i := range headers {
		if headers[i].Key == key {
			headers[i].Value = []byte(value)
			return headers
		}
	}
	return append(headers, kafka.Header{Key: key, Value: []byte(value)})
}

func headerValue(headers []kafka.Header, key string) string {
	for _, h := range headers {
		if h.Key == key {
			return string(h.Value)
		}
	}
	return ""
}

func topicForMessage(writer *kafka.Writer, msg kafka.Message) string {
	if msg.Topic != "" {
		return msg.Topic
	}
	if writer != nil {
		return writer.Topic
	}
	return ""
}
