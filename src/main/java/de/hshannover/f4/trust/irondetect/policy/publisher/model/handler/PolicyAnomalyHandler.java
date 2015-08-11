package de.hshannover.f4.trust.irondetect.policy.publisher.model.handler;

import static de.hshannover.f4.trust.irondetect.policy.publisher.util.PolicyStrings.DEFAULT_ADMINISTRATIVE_DOMAIN;

import java.util.List;
import java.util.Map;

import de.hshannover.f4.trust.irondetect.policy.publisher.model.identifier.Anomaly;

public class PolicyAnomalyHandler implements PolicyHandler<de.hshannover.f4.trust.irondetect.model.Anomaly> {

	@Override
	public Anomaly toIdentifier(de.hshannover.f4.trust.irondetect.model.Anomaly data) {

		List<String> expressions = HandlerHelper.transformHintExpression(data.getHintSet());
		Map<String, List<String>> context = HandlerHelper.transformContext(data.getContextSet());

		Anomaly identifier = new Anomaly(data.getId(), expressions, DEFAULT_ADMINISTRATIVE_DOMAIN, context);

		return identifier;
	}

	@Override
	public Class<de.hshannover.f4.trust.irondetect.model.Anomaly> handle() {
		return de.hshannover.f4.trust.irondetect.model.Anomaly.class;
	}

}
