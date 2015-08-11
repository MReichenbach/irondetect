package de.hshannover.f4.trust.irondetect.policy.publisher.model.identifier.exception;

public class AnomalyException extends PolicyIdentifierException{

	public AnomalyException(String msg) {
		super(msg);
	}

	public AnomalyException(String msg, String... args) {
		this(String.format(msg, (Object[]) args));
	}

}
