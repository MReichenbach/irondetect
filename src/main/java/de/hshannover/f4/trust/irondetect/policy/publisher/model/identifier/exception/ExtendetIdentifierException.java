package de.hshannover.f4.trust.irondetect.policy.publisher.model.identifier.exception;

public class ExtendetIdentifierException extends Exception {

	private static final long serialVersionUID = -660777274915469023L;

	public ExtendetIdentifierException(String msg) {
		super(msg);
	}

	@Override
	public String toString() {
		return getClass().getSimpleName() + " [Message: " + super.getMessage() + "]";
	}
}
