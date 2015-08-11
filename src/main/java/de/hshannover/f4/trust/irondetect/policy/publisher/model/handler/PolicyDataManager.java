package de.hshannover.f4.trust.irondetect.policy.publisher.model.handler;

import de.hshannover.f4.trust.irondetect.model.PolicyData;
import de.hshannover.f4.trust.irondetect.policy.publisher.model.identifier.ExtendetIdentifier;

public class PolicyDataManager {

	@SuppressWarnings({ "rawtypes", "unchecked" })
	public static ExtendetIdentifier transformPolicyData(PolicyData data) throws ClassNotFoundException,
			InstantiationException, IllegalAccessException {

		PolicyHandler handler = PolicyHandlerManager.getHandlerFor(data);

		return handler.toIdentifier(data);
	}

}