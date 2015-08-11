package de.hshannover.f4.trust.irondetect.policy.publisher.test;

import de.hshannover.f4.trust.ifmapj.identifier.IdentifierWithAd;
import de.hshannover.f4.trust.irondetect.policy.publisher.model.identifier.ExtendetIdentifier;

public class Signature6 extends IdentifierWithAd implements ExtendetIdentifier {

	private String mID;

	private String mFeatureExpressions;

	public Signature6(String id, String featureExpressions, String admDom) {
		super(admDom);

		mID = id;
		mFeatureExpressions = featureExpressions;
	}

	public String getID() {
		return mID;
	}

	public void setID(String ID) {
		this.mID = ID;
	}

	public String getFeatureExpressions() {
		return mFeatureExpressions;
	}

	public void setFeatureExpressions(String featureExpressions) {
		this.mFeatureExpressions = featureExpressions;
	}



}
