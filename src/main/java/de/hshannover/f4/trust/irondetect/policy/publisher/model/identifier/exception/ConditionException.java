package de.hshannover.f4.trust.irondetect.policy.publisher.model.identifier.exception;

public class ConditionException extends PolicyIdentifierException{

	public ConditionException(String msg) {
		super(msg);
	}

	public ConditionException(String msg, String... args) {
		this(String.format(msg, (Object[]) args));
	}

}
