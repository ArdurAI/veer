package audit

// The types below are opaque runtime or constructor values. Their supported
// wire projections are the explicit canonical Event, Segment, and export
// artifacts; allowing generic encoders to turn private fields into `{}` would
// silently discard evidence.

func serializationForbidden() ([]byte, error) { return nil, ErrSerializationForbidden }

func (Stream) MarshalJSON() ([]byte, error)   { return serializationForbidden() }
func (Stream) MarshalText() ([]byte, error)   { return serializationForbidden() }
func (Stream) MarshalBinary() ([]byte, error) { return serializationForbidden() }
func (Stream) GobEncode() ([]byte, error)     { return serializationForbidden() }

func (ActorRef) MarshalJSON() ([]byte, error)   { return serializationForbidden() }
func (ActorRef) MarshalText() ([]byte, error)   { return serializationForbidden() }
func (ActorRef) MarshalBinary() ([]byte, error) { return serializationForbidden() }
func (ActorRef) GobEncode() ([]byte, error)     { return serializationForbidden() }

func (RequestRef) MarshalJSON() ([]byte, error)   { return serializationForbidden() }
func (RequestRef) MarshalText() ([]byte, error)   { return serializationForbidden() }
func (RequestRef) MarshalBinary() ([]byte, error) { return serializationForbidden() }
func (RequestRef) GobEncode() ([]byte, error)     { return serializationForbidden() }

func (TargetRef) MarshalJSON() ([]byte, error)   { return serializationForbidden() }
func (TargetRef) MarshalText() ([]byte, error)   { return serializationForbidden() }
func (TargetRef) MarshalBinary() ([]byte, error) { return serializationForbidden() }
func (TargetRef) GobEncode() ([]byte, error)     { return serializationForbidden() }

func (DecisionRef) MarshalJSON() ([]byte, error)   { return serializationForbidden() }
func (DecisionRef) MarshalText() ([]byte, error)   { return serializationForbidden() }
func (DecisionRef) MarshalBinary() ([]byte, error) { return serializationForbidden() }
func (DecisionRef) GobEncode() ([]byte, error)     { return serializationForbidden() }

func (OperationRef) MarshalJSON() ([]byte, error)   { return serializationForbidden() }
func (OperationRef) MarshalText() ([]byte, error)   { return serializationForbidden() }
func (OperationRef) MarshalBinary() ([]byte, error) { return serializationForbidden() }
func (OperationRef) GobEncode() ([]byte, error)     { return serializationForbidden() }

func (AttemptRef) MarshalJSON() ([]byte, error)   { return serializationForbidden() }
func (AttemptRef) MarshalText() ([]byte, error)   { return serializationForbidden() }
func (AttemptRef) MarshalBinary() ([]byte, error) { return serializationForbidden() }
func (AttemptRef) GobEncode() ([]byte, error)     { return serializationForbidden() }

func (ElevationRef) MarshalJSON() ([]byte, error)   { return serializationForbidden() }
func (ElevationRef) MarshalText() ([]byte, error)   { return serializationForbidden() }
func (ElevationRef) MarshalBinary() ([]byte, error) { return serializationForbidden() }
func (ElevationRef) GobEncode() ([]byte, error)     { return serializationForbidden() }

func (Checkpoint) MarshalJSON() ([]byte, error)   { return serializationForbidden() }
func (Checkpoint) MarshalText() ([]byte, error)   { return serializationForbidden() }
func (Checkpoint) MarshalBinary() ([]byte, error) { return serializationForbidden() }
func (Checkpoint) GobEncode() ([]byte, error)     { return serializationForbidden() }

func (Record) MarshalJSON() ([]byte, error)   { return serializationForbidden() }
func (Record) MarshalText() ([]byte, error)   { return serializationForbidden() }
func (Record) MarshalBinary() ([]byte, error) { return serializationForbidden() }
func (Record) GobEncode() ([]byte, error)     { return serializationForbidden() }

func (SequenceRange) MarshalJSON() ([]byte, error)   { return serializationForbidden() }
func (SequenceRange) MarshalText() ([]byte, error)   { return serializationForbidden() }
func (SequenceRange) MarshalBinary() ([]byte, error) { return serializationForbidden() }
func (SequenceRange) GobEncode() ([]byte, error)     { return serializationForbidden() }

func (Hold) MarshalJSON() ([]byte, error)   { return serializationForbidden() }
func (Hold) MarshalText() ([]byte, error)   { return serializationForbidden() }
func (Hold) MarshalBinary() ([]byte, error) { return serializationForbidden() }
func (Hold) GobEncode() ([]byte, error)     { return serializationForbidden() }

func (RetentionDecision) MarshalJSON() ([]byte, error)   { return serializationForbidden() }
func (RetentionDecision) MarshalText() ([]byte, error)   { return serializationForbidden() }
func (RetentionDecision) MarshalBinary() ([]byte, error) { return serializationForbidden() }
func (RetentionDecision) GobEncode() ([]byte, error)     { return serializationForbidden() }
