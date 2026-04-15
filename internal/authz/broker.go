package authz

import "context"

type BrokerOperation string

const (
	BrokerOperationPublish BrokerOperation = "publish"
	BrokerOperationConsume BrokerOperation = "consume"
)

type BrokerInteraction struct {
	SourceService string
	TargetService string
	Broker        string
	Resource      string
	MessageType   string
}

type BrokerAuthzAdapter interface {
	NormalizePublish(BrokerInteraction) AuthzRequest
	NormalizeConsume(BrokerInteraction) AuthzRequest
	AuthorizePublish(context.Context, BrokerInteraction) (CheckResponse, error)
	AuthorizeConsume(context.Context, BrokerInteraction) (CheckResponse, error)
}

type GenericBrokerAdapter struct {
	authorizer *Authorizer
}

func NewGenericBrokerAdapter(cfg Config) (*GenericBrokerAdapter, error) {
	authorizer, err := NewAuthorizer(cfg)
	if err != nil {
		return nil, err
	}
	return &GenericBrokerAdapter{authorizer: authorizer}, nil
}

func (a *GenericBrokerAdapter) NormalizePublish(interaction BrokerInteraction) AuthzRequest {
	return NewBrokerAuthzRequest(interaction, BrokerOperationPublish)
}

func (a *GenericBrokerAdapter) NormalizeConsume(interaction BrokerInteraction) AuthzRequest {
	return NewBrokerAuthzRequest(interaction, BrokerOperationConsume)
}

func (a *GenericBrokerAdapter) AuthorizePublish(ctx context.Context, interaction BrokerInteraction) (CheckResponse, error) {
	return a.authorizer.Authorize(ctx, a.NormalizePublish(interaction))
}

func (a *GenericBrokerAdapter) AuthorizeConsume(ctx context.Context, interaction BrokerInteraction) (CheckResponse, error) {
	return a.authorizer.Authorize(ctx, a.NormalizeConsume(interaction))
}

func NewBrokerAuthzRequest(interaction BrokerInteraction, operation BrokerOperation) AuthzRequest {
	return AuthzRequest{
		Source:      interaction.SourceService,
		Target:      interaction.TargetService,
		Transport:   TransportBroker,
		Operation:   string(operation),
		Resource:    interaction.Resource,
		Broker:      interaction.Broker,
		MessageType: interaction.MessageType,
	}.Normalize()
}
