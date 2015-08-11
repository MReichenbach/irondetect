package de.hshannover.f4.trust.irondetect.policy.publisher.model.handler;

import static de.hshannover.f4.trust.irondetect.policy.publisher.util.PolicyStrings.DEFAULT_ADMINISTRATIVE_DOMAIN;

import java.util.List;
import java.util.Map;

import de.hshannover.f4.trust.irondetect.policy.publisher.model.identifier.Signature;

public class PolicySignatureHandler implements PolicyHandler<de.hshannover.f4.trust.irondetect.model.Signature> {

	@Override
	public Signature toIdentifier(de.hshannover.f4.trust.irondetect.model.Signature data) {

		List<String> expressions = HandlerHelper.transformFeatureExpression(data.getFeatureSet());
		Map<String, List<String>> context = HandlerHelper.transformContext(data.getContextSet());

		Signature identifier = new Signature(data.getId(), expressions, DEFAULT_ADMINISTRATIVE_DOMAIN, context);

		return identifier;
	}

	@Override
	public Class<de.hshannover.f4.trust.irondetect.model.Signature> handle() {
		return de.hshannover.f4.trust.irondetect.model.Signature.class;
	}

}
