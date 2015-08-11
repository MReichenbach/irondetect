/*
 * #%L
 * =====================================================
 *   _____                _     ____  _   _       _   _
 *  |_   _|_ __ _   _ ___| |_  / __ \| | | | ___ | | | |
 *    | | | '__| | | / __| __|/ / _` | |_| |/ __|| |_| |
 *    | | | |  | |_| \__ \ |_| | (_| |  _  |\__ \|  _  |
 *    |_| |_|   \__,_|___/\__|\ \__,_|_| |_||___/|_| |_|
 *                             \____/
 * 
 * =====================================================
 * 
 * Hochschule Hannover
 * (University of Applied Sciences and Arts, Hannover)
 * Faculty IV, Dept. of Computer Science
 * Ricklinger Stadtweg 118, 30459 Hannover, Germany
 * 
 * Email: trust@f4-i.fh-hannover.de
 * Website: http://trust.f4.hs-hannover.de/
 * 
 * This file is part of irondetect, version 0.0.8,
 * implemented by the Trust@HsH research group at the Hochschule Hannover.
 * %%
 * Copyright (C) 2010 - 2015 Trust@HsH
 * %%
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * #L%
 */
package de.hshannover.f4.trust.irondetect.gui;



import java.util.Date;

import de.hshannover.f4.trust.irondetect.util.Helper;

public class ResultObject {

	private String index;
	
	private String device;

	private ResultObjectType type;

	private String id;

	private boolean value;

	private String timestamp;

	public ResultObject(String device, ResultObjectType type, String id, boolean value) {
		super();
		this.index = "0";
		this.device = device;
		this.type = type;
		this.id = id;
		this.value = value;
		this.timestamp = Helper.getTimeAsXsdDateTime(new Date());
	}

	public String getIndex() {
		return this.index;
	}
	
	public void setIndex(int index) {
		this.index = Integer.toString(index);
	}
	
	public String getDevice() {
		return this.device;
	}

	public ResultObjectType getType() {
		return this.type;
	}

	public String getId() {
		return this.id;
	}

	public boolean getValue() {
		return this.value;
	}

	public String getTimeStamp() {
		return this.timestamp;
	}

}
