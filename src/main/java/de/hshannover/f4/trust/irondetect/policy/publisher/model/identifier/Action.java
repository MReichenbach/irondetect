package de.hshannover.f4.trust.irondetect.policy.publisher.model.identifier;

import static de.hshannover.f4.trust.irondetect.policy.publisher.model.identifier.exception.PolicyIdentifierException.MSG_EXPRESSION_NOT_PRESENT;
import static de.hshannover.f4.trust.irondetect.policy.publisher.model.identifier.exception.PolicyIdentifierException.MSG_INDEX_TOO_BIG_FOR_EXPRESSIONS;

import java.util.ArrayList;
import java.util.List;

import de.hshannover.f4.trust.ifmapj.identifier.IdentifierWithAd;
import de.hshannover.f4.trust.ifmapj.identifier.Identity;
import de.hshannover.f4.trust.irondetect.policy.publisher.model.identifier.exception.ActionException;
import de.hshannover.f4.trust.irondetect.policy.publisher.util.Check;

/**
 * An {@link Action} is an extended identifier. It is represented by an {@link Identity} identifier with IdentityType = other
 *  ,other-type = extended and with an empty administrative domain.
 * 
 * @author Marcel Reichenbach
 */
public class Action extends IdentifierWithAd implements ExtendetIdentifier {

	private String mID;

	private List<String> mExpressions;

	/**
	 * The {@link Action} constructor. Checks the parameter, if null throws {@link NullPointerException}.
	 * 
	 * @param id The {@link Action}-ID
	 * @param expressions All expressions for the {@link Action}
	 * @param admDom The administrative domain for {@link Action}
	 * @param context All context for the {@link Action}
	 */
	public Action(String id, List<String> expressions, String admDom) {
		super(admDom);

		Check.ifNull(id, String.format(Check.MSG_PARAMETER_IS_NULL, "id"));
		Check.ifNull(expressions, String.format(Check.MSG_PARAMETER_IS_NULL, "expressions"));
		Check.ifNull(admDom, String.format(Check.MSG_PARAMETER_IS_NULL, "admDom"));

		setId(id);
		mExpressions = expressions;
	}

	/**
	 * The {@link Action} constructor. Checks the parameter, if null throws {@link NullPointerException}.
	 * Initializes with an empty expression-collection.
	 * 
	 * @param id The {@link Action}-ID
	 * @param admDom The administrative domain for {@link Action}
	 */
	public Action(String id, String admDom) {
		super(admDom);

		Check.ifNull(id, String.format(Check.MSG_PARAMETER_IS_NULL, "id"));
		Check.ifNull(admDom, String.format(Check.MSG_PARAMETER_IS_NULL, "admDom"));

		mExpressions = new ArrayList<String>();

		setId(id);
	}

	/**
	 * 
	 * @return {@link Action}-ID
	 */
	public String getID() {
		return mID;
	}

	/**
	 * Set the {@link Action}-ID.
	 * Checks the parameter id, if null throws {@link NullPointerException}.
	 * 
	 * @param id {@link Action}-ID
	 */
	public void setId(String id) {
		Check.ifNull(id, String.format(Check.MSG_PARAMETER_IS_NULL, "id"));

		mID = id;
	}

	/**
	 * 
	 * @return A expressions copy
	 */
	public List<String> getExpressions() {
		return new ArrayList<String>(mExpressions);
	}

	/**
	 * Add a new expression.
	 * Checks the parameter expression, if null throws {@link NullPointerException}.
	 * 
	 * @param expression The expression String
	 */
	public void addFeatureExpression(String expression) {
		Check.ifNull(expression, String.format(Check.MSG_PARAMETER_IS_NULL, "expression"));

		mExpressions.add(expression);
	}

	/**
	 * Checks the parameter index, if index < 0 throws {@link IndexOutOfBoundsException}.
	 * 
	 * @param index
	 * @throws ActionException If the index is too big for expression list-size.
	 */
	public void removeExpression(int index) throws ActionException {
		Check.indexNumber(index, String.format(Check.MSG_IS_LESS_THAN_ZERO, index));

		if (index < mExpressions.size()) {
			mExpressions.remove(index);
		} else {
			throw new ActionException(MSG_INDEX_TOO_BIG_FOR_EXPRESSIONS, String.valueOf(index));
		}
	}

	/**
	 * Checks the parameter, if null throws {@link NullPointerException}.
	 * 
	 * @param expression
	 * @throws ActionException If the expression is not found
	 */
	public void removeExpression(String expression) throws ActionException {
		Check.ifNull(expression, String.format(Check.MSG_PARAMETER_IS_NULL, "expression"));

		if (mExpressions.contains(expression)) {
			mExpressions.remove(expression);
		} else {
			throw new ActionException(MSG_EXPRESSION_NOT_PRESENT, expression);
		}
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();

		sb.append(getClass().getSimpleName());
		sb.append('(');
		sb.append(getID());
		sb.append(' ');
		sb.append(':');

		for (String s : getExpressions()) {
			sb.append(' ');
			sb.append(s);
		}

		sb.append(')');

		return sb.toString();
	}

}
