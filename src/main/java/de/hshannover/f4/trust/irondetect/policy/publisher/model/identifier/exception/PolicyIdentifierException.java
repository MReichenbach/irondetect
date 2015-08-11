package de.hshannover.f4.trust.irondetect.policy.publisher.model.identifier.exception;

public class PolicyIdentifierException extends ExtendetIdentifierException {

	private static final long serialVersionUID = -2158186843530914788L;

	public static final String MSG_INDEX_TOO_BIG_FOR_EXPRESSIONS = "Index(%s) is bigger than expressions-size!";

	public static final String MSG_EXPRESSION_NOT_PRESENT = "Expression(%s) not present!";

	public static final String MSG_CONTEXT_ID_NOT_PRESENT = "ContextID(%s) not present!";

	public static final String MSG_CONTEXT_FOR_CONTEXT_ID_NOT_PRESENT = "Context(%s) for ContextID(%s) not present!";

	public static final String MSG_INDEX_TOO_BIG_FOR_CONTEXT_ID = "Index(%s) is bigger than context-size!";

	public PolicyIdentifierException(String msg) {
		super(msg);
	}

	public PolicyIdentifierException(String msg, String... args) {
		this(String.format(msg, (Object[]) args));
	}

}
