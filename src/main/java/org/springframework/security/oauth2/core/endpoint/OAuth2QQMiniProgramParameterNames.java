package org.springframework.security.oauth2.core.endpoint;

/*-
 * #%L
 * spring-boot-starter-qq-miniprogram
 * %%
 * Copyright (C) 2022 徐晓伟工作室
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

/**
 * QQ小程序 参数名称
 *
 * @author xuxiaowei
 * @since 0.0.1
 * @see OAuth2ParameterNames 在 OAuth 参数注册表中定义并由授权端点、令牌端点和令牌撤销端点使用的标准和自定义（非标准）参数名称。
 */
public interface OAuth2QQMiniProgramParameterNames {

	/**
	 * AppID(小程序ID)
	 */
	String APPID = "appid";

	/**
	 * AppSecret(小程序密钥)
	 */
	String SECRET = "secret";

	/**
	 * @see <a href= "https://q.qq.com/wiki/develop/game/server/open-port/login.html">登录 -
	 * code2Session</a>
	 *
	 * @see OAuth2ParameterNames#CODE
	 */
	String JS_CODE = "js_code";

	/**
	 * 用户唯一标识
	 *
	 * @see <a href= "https://q.qq.com/wiki/develop/game/server/open-port/login.html">登录 -
	 * code2Session</a>
	 */
	String OPENID = "openid";

	/**
	 * 如果开发者拥有多个移动应用、网站应用、和小程序，可通过 UnionID 来区分用户的唯一性，因为只要是同一个QQ互联帐号下的移动应用、网站应用和小程序，用户的
	 * UnionID 是唯一的。换句话说，同一用户，对同一个QQ互联平台下的不同应用，unionid是相同的。详见 <a href=
	 * "https://q.qq.com/wiki/develop/game/frame/open-ability/union-id.html">UnionID
	 * 机制说明</a>。
	 */
	String UNIONID = "unionid";

	/**
	 * 会话密钥
	 *
	 * @see <a href= "https://q.qq.com/wiki/develop/game/server/open-port/login.html">登录 -
	 * code2Session</a>
	 */
	String SESSION_KEY = "sessionKey";

}
