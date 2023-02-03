package org.springframework.security.oauth2.server.authorization.client;

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

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

import java.io.Serializable;

/**
 * 登录凭证校验 返回值
 *
 * @author xuxiaowei
 * @since 0.0.1
 * @see <a href=
 * "https://q.qq.com/wiki/develop/game/server/open-port/login.html">登录凭证校验</a>
 */
@Data
public class QQMiniProgramTokenResponse implements Serializable {

	private static final long serialVersionUID = 1L;

	/**
	 * 用户唯一标识，<a href= "https://q.qq.com/wiki/develop/game/server/open-port/login.html">登录
	 * - code2Session</a>
	 */
	private String openid;

	/**
	 * 会话密钥
	 */
	@JsonProperty("session_key")
	private String sessionKey;

	/**
	 * 如果开发者拥有多个移动应用、网站应用、和小程序，可通过 UnionID 来区分用户的唯一性，因为只要是同一个QQ互联帐号下的移动应用、网站应用和小程序，用户的
	 * UnionID 是唯一的。换句话说，同一用户，对同一个QQ互联平台下的不同应用，unionid是相同的。详见 <a href=
	 * "https://q.qq.com/wiki/develop/game/frame/open-ability/union-id.html">UnionID
	 * 机制说明</a>。
	 */
	private String unionid;

	/**
	 * 错误码
	 */
	private String errcode;

	/**
	 * 错误信息
	 */
	private String errmsg;

}
