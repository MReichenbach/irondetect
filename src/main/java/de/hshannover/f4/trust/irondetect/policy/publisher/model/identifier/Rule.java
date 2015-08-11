package de.hshannover.f4.trust.irondetect.policy.publisher.model.identifier;

import de.hshannover.f4.trust.ifmapj.identifier.IdentifierWithAd;
import de.hshannover.f4.trust.ifmapj.identifier.Identity;
import de.hshannover.f4.trust.irondetect.policy.publisher.util.Check;

/**
 * An Rule is an extended identifier. It is represented by an {@link Identity} identifier with IdentityType = other
 *  ,other-type = extended and with an empty administrative domain.
 * 
 * @author Marcel Reichenbach
 */
public class Rule extends IdentifierWithAd implements ExtendetIdentifier {

	private String mID;

	/**
	 * The {@link Rule} constructor. Checks the parameter, if null throws {@link NullPointerException}.
	 * 
	 * @param id The {@link Rule}-ID
	 * @param admDom The administrative domain for {@link Rule}
	 */
	public Rule(String id, String admDom) {
		super(admDom);

		Check.ifNull(id, String.format(Check.MSG_PARAMETER_IS_NULL, "id"));
		Check.ifNull(admDom, String.format(Check.MSG_PARAMETER_IS_NULL, "admDom"));

		setId(id);
	}

	/**
	 * 
	 * @return {@link Rule}-ID
	 */
	public String getID() {
		return mID;
	}

	/**
	 * Set the {@link Rule}-ID.
	 * Checks the parameter id, if null throws {@link NullPointerException}.
	 * 
	 * @param id {@link Rule}-ID
	 */
	public void setId(String id) {
		Check.ifNull(id, String.format(Check.MSG_PARAMETER_IS_NULL, "id"));

		mID = id;
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();

		sb.append(getClass().getSimpleName());
		sb.append('(');
		sb.append(getID());
		sb.append(')');

		return sb.toString();
	}

}
