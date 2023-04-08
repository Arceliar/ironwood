package network

// TODO add data fields to provide context, when appropriate

type EncodeError struct{}

func (e EncodeError) Error() string {
	return "EncodeError"
}

type DecodeError struct{}

func (e DecodeError) Error() string {
	return "DecodeError"
}

type ClosedError struct{}

func (e ClosedError) Error() string {
	return "ClosedError"
}

type DeadlineError struct{}

func (e DeadlineError) Error() string {
	return "DeadlineError"
}

type BadMessageError struct{}

func (e BadMessageError) Error() string {
	return "BadMessageError"
}

type EmptyMessageError struct{}

func (e EmptyMessageError) Error() string {
	return "EmptyMessageError"
}

type OversizedMessageError struct{}

func (e OversizedMessageError) Error() string {
	return "OversizedMessageError"
}

type UnrecognizedMessageError struct{}

func (e UnrecognizedMessageError) Error() string {
	return "UnrecognizedMessageError"
}

type PeerNotFoundError struct{}

func (e PeerNotFoundError) Error() string {
	return "PeerNotFoundError"
}

type BadAddressError struct{}

func (e BadAddressError) Error() string {
	return "BadAddressError"
}

type BadKeyError struct{}

func (e BadKeyError) Error() string {
	return "BadKeyError"
}
