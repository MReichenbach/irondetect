package de.hshannover.f4.trust.irondetect.policy.publisher.model.identifier;

import static de.hshannover.f4.trust.irondetect.policy.publisher.model.identifier.exception.PolicyIdentifierException.MSG_EXPRESSION_NOT_PRESENT;
import static de.hshannover.f4.trust.irondetect.policy.publisher.model.identifier.exception.PolicyIdentifierException.MSG_INDEX_TOO_BIG_FOR_EXPRESSIONS;

import java.util.ArrayList;
import java.util.List;

import de.hshannover.f4.trust.ifmapj.identifier.IdentifierWithAd;
import de.hshannover.f4.trust.ifmapj.identifier.Identity;
import de.hshannover.f4.trust.irondetect.policy.publisher.model.identifier.exception.HintException;
import de.hshannover.f4.trust.irondetect.policy.publisher.util.Check;

/**
 * An {@link Hint} is an extended identifier. It is represented by an {@link Identity} identifier with IdentityType = other
 *  ,other-type = extended and with an empty administrative domain.
 * 
 * @author Marcel Reichenbach
 */
public class Hint extends IdentifierWithAd implements ExtendetIdentifier {

	private String mID;

	private List<String> mExpressions;

	/**
	 * The {@link Hint} constructor. Checks the parameter, if null throws {@link NullPointerException}.
	 * 
	 * @param id The {@link Hint}-ID
	 * @param expressions All expressions for the {@link Hint}
	 * @param admDom The administrative domain for {@link Hint}
	 */
	public Hint(String id, List<String> expressions, String admDom) {
		super(admDom);

		Check.ifNull(id, String.format(Check.MSG_PARAMETER_IS_NULL, "id"));
		Check.ifNull(expressions, String.format(Check.MSG_PARAMETER_IS_NULL, "expressions"));
		Check.ifNull(admDom, String.format(Check.MSG_PARAMETER_IS_NULL, "admDom"));

		setId(id);
		mExpressions = expressions;
	}

	/**
	 * The {@link Hint} constructor. Checks the parameter, if null throws {@link NullPointerException}.
	 * Initializes with an empty expression- and context-collection.
	 * 
	 * @param id The {@link Hint}-ID
	 * @param admDom The administrative domain for {@link Hint}
	 */
	public Hint(String id, String admDom) {
		super(admDom);

		Check.ifNull(id, String.format(Check.MSG_PARAMETER_IS_NULL, "id"));
		Check.ifNull(admDom, String.format(Check.MSG_PARAMETER_IS_NULL, "admDom"));

		mExpressions = new ArrayList<String>();

		setId(id);
	}

	/**
	 * 
	 * @return {@link Hint}-ID
	 */
	public String getID() {
		return mID;
	}

	/**
	 * Set the {@link Hint}-ID.
	 * Checks the parameter id, if null throws {@link NullPointerException}.
	 * 
	 * @param id {@link Hint}-ID
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
	 * @throws HintException If the index is too big for expression list-size.
	 */
	public void removeExpression(int index) throws HintException {
		Check.indexNumber(index, String.format(Check.MSG_IS_LESS_THAN_ZERO, index));

		if (index < mExpressions.size()) {
			mExpressions.remove(index);
		} else {
			throw new HintException(MSG_INDEX_TOO_BIG_FOR_EXPRESSIONS, String.valueOf(index));
		}
	}

	/**
	 * Checks the parameter, if null throws {@link NullPointerException}.
	 * 
	 * @param expression
	 * @throws HintException If the expression is not found
	 */
	public void removeExpression(String expression) throws HintException {
		Check.ifNull(expression, String.format(Check.MSG_PARAMETER_IS_NULL, "expression"));

		if (mExpressions.contains(expression)) {
			mExpressions.remove(expression);
		} else {
			throw new HintException(MSG_EXPRESSION_NOT_PRESENT, expression);
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
