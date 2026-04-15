package natsadapter

import (
	"context"
	"errors"

	"authz-system/internal/authz"

	"github.com/nats-io/nats.go"
)

const (
	BrokerNameNATS        = "nats"
	HeaderServiceName     = "X-Service-Name"
	HeaderMessageType     = "X-Message-Type"
	DefaultTargetService  = "payments"
	DefaultRequestedTopic = "payments.requested"
)

var (
	ErrMissingServiceName = errors.New("nats message missing X-Service-Name header")
	ErrMissingMessageType = errors.New("nats message missing X-Message-Type header")
	ErrMissingSubject     = errors.New("nats message subject is empty")
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

func (a *Adapter) Publish(ctx context.Context, conn *nats.Conn, subject string, data []byte, sourceService, messageType string) error {
	if subject == "" {
		return ErrMissingSubject
	}

	interaction := authz.BrokerInteraction{
		SourceService: sourceService,
		TargetService: a.targetService,
		Broker:        BrokerNameNATS,
		Resource:      subject,
		MessageType:   messageType,
	}
	if _, err := a.broker.AuthorizePublish(ctx, interaction); err != nil {
		return err
	}

	msg := &nats.Msg{
		Subject: subject,
		Header: nats.Header{
			HeaderServiceName: []string{sourceService},
			HeaderMessageType: []string{messageType},
		},
		Data: data,
	}
	return conn.PublishMsg(msg)
}

func (a *Adapter) AuthorizeConsume(ctx context.Context, msg *nats.Msg) error {
	if msg == nil || msg.Subject == "" {
		return ErrMissingSubject
	}
	sourceService, err := ServiceNameFromHeaders(msg.Header)
	if err != nil {
		return err
	}
	messageType, err := MessageTypeFromHeaders(msg.Header)
	if err != nil {
		return err
	}

	interaction := authz.BrokerInteraction{
		SourceService: sourceService,
		TargetService: a.targetService,
		Broker:        BrokerNameNATS,
		Resource:      msg.Subject,
		MessageType:   messageType,
	}
	_, err = a.broker.AuthorizeConsume(ctx, interaction)
	return err
}

func ServiceNameFromHeaders(headers nats.Header) (string, error) {
	v := headers.Get(HeaderServiceName)
	if v == "" {
		return "", ErrMissingServiceName
	}
	return v, nil
}

func MessageTypeFromHeaders(headers nats.Header) (string, error) {
	v := headers.Get(HeaderMessageType)
	if v == "" {
		return "", ErrMissingMessageType
	}
	return v, nil
}
