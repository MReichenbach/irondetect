package de.hshannover.f4.trust.irondetect.policy.publisher.util;

/**
 * A simple helper Class
 * 
 * @author Marcel Reichenbach
 */
public class Check {

	public static final String MSG_PARAMETER_IS_NULL = "Parameter(%s) can not be null!";

	public static final String MSG_IS_LESS_THAN_ZERO = "Index(%s) can not be less than zero!";

	/**
	 * If obj is null throw a {@link NullPointerException} with message.
	 * 
	 * @param obj any Object
	 * @param msg NullPointer-Error massage
	 * @throws NullPointerException with massage msg
	 */
	public static void ifNull(Object obj, String msg) throws NullPointerException {
		if (obj == null) {
			throw new NullPointerException(msg);
		}
	}

	/**
	 * If index is less than zero throw a {@link IndexOutOfBoundsException} with message.
	 * 
	 * @param obj any index
	 * @param msg IndexOutOfBounds-Error massage
	 * @throws IndexOutOfBoundsException with massage msg
	 */
	public static void indexNumber(int index, String msg) throws IndexOutOfBoundsException {
		if (index < 0) {
			throw new IndexOutOfBoundsException(msg);
		}
	}

}