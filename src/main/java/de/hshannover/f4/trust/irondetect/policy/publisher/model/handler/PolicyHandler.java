package de.hshannover.f4.trust.irondetect.policy.publisher.model.handler;

import de.hshannover.f4.trust.irondetect.model.PolicyData;
import de.hshannover.f4.trust.irondetect.policy.publisher.model.identifier.ExtendetIdentifier;

public interface PolicyHandler<T extends PolicyData> {

	public ExtendetIdentifier toIdentifier(T data);

	public Class<T> handle();
}
