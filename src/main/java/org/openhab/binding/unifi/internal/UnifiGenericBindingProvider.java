/**
 * Copyright (c) 2010-2015, openHAB.org and others.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package org.openhab.binding.unifi.internal;

import org.openhab.binding.unifi.UnifiBindingProvider;
import org.openhab.core.binding.BindingConfig;
import org.openhab.core.items.Item;
import org.openhab.model.item.binding.AbstractGenericBindingProvider;
import org.openhab.model.item.binding.BindingConfigParseException;


/**
 * This class is responsible for parsing the binding configuration.
 * 
 * @author Ondrej Pecta
 * @since 1.9.0
 */
public class UnifiGenericBindingProvider extends AbstractGenericBindingProvider implements UnifiBindingProvider {

	/**
	 * {@inheritDoc}
	 */
	public String getBindingType() {
		return "unifi";
	}

	/**
	 * @{inheritDoc}
	 */
	@Override
	public void validateItemType(Item item, String bindingConfig) throws BindingConfigParseException {
		//if (!(item instanceof SwitchItem || item instanceof DimmerItem)) {
		//	throw new BindingConfigParseException("item '" + item.getName()
		//			+ "' is of type '" + item.getClass().getSimpleName()
		//			+ "', only Switch- and DimmerItems are allowed - please check your *.items configuration");
		//}
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public void processBindingConfiguration(String context, Item item, String bindingConfig) throws BindingConfigParseException {
		super.processBindingConfiguration(context, item, bindingConfig);
		UnifiBindingConfig config = null;
		if( bindingConfig.contains("#")) {
			int hash = bindingConfig.indexOf("#");
			String type = bindingConfig.substring(0, hash);
			String mac = bindingConfig.substring(hash + 1);
			config = new UnifiBindingConfig(type, mac);
		}
		else {
			config = new UnifiBindingConfig(bindingConfig);
		}
		addBindingConfig(item, config);
	}

	public String getItemType(String itemName) {
		final UnifiBindingConfig config = (UnifiBindingConfig) this.bindingConfigs.get(itemName);
		return config != null ? (config.getType()) : null;
	}

	public String getItemId(String itemName) {
		final UnifiBindingConfig config = (UnifiBindingConfig) this.bindingConfigs.get(itemName);
		return config != null ? (config.getId()) : null;
	}

	public BindingConfig getItemConfig(String itemName) {
		final UnifiBindingConfig config = (UnifiBindingConfig) this.bindingConfigs.get(itemName);
		return config;
	}

	/**
	 * This is a helper class holding binding specific configuration details
	 * 
	 * @author Ondrej Pecta
	 * @since 1.9.0
	 */
	class UnifiBindingConfig implements BindingConfig {
		// put member fields here which holds the parsed values
		private String type;
		private String id = "";

		public String getType() {
			return type;
		}

		public String getId() {
			return id;
		}

		UnifiBindingConfig(String type) {
			this.type = type;
		}

		UnifiBindingConfig(String type, String id) {
			this.type = type;
			this.id = id;
		}
	}
	
	
}
