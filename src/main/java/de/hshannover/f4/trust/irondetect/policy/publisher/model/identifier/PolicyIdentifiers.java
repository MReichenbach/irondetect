package de.hshannover.f4.trust.irondetect.policy.publisher.model.identifier;

import java.util.List;
import java.util.Map;

public class PolicyIdentifiers {

	/**
	 * Create an signature identifier with the given id, featureExpressions and the given
	 * administrative-domain.
	 *
	 * @param id the id of the signature
	 * @param featureExpressions the featureExpressions string of the signature
	 * @param admDom the administrative-domain of the signature
	 * @param context the context of the signature
	 * @return the new {@link Signature} instance
	 */
	public static Signature createSignature(String id, List<String> featureExpressions, String admDom,
			Map<String, List<String>> context) {
		return new Signature(id, featureExpressions, admDom, context);
	}

}
