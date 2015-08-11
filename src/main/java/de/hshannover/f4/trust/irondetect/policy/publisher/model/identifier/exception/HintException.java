package de.hshannover.f4.trust.irondetect.policy.publisher.model.identifier.exception;

public class HintException extends PolicyIdentifierException{

	public HintException(String msg) {
		super(msg);
	}

	public HintException(String msg, String... args) {
		this(String.format(msg, (Object[]) args));
	}

}
