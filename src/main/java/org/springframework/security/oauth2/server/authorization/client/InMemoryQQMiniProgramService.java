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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.QQMiniProgramAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.Customizer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2QQMiniProgramParameterNames;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2TokenEndpointConfigurer;
import org.springframework.security.oauth2.server.authorization.exception.AppidQQMiniProgramException;
import org.springframework.security.oauth2.server.authorization.properties.QQMiniProgramProperties;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2QQMiniProgramEndpointUtils;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.util.Assert;
import org.springframework.web.client.RestTemplate;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * QQ小程序 账户服务接口 基于内存的实现
 *
 * @author xuxiaowei
 * @since 0.0.1
 */
public class InMemoryQQMiniProgramService implements QQMiniProgramService {

	private final QQMiniProgramProperties qqMiniProgramProperties;

	public InMemoryQQMiniProgramService(QQMiniProgramProperties qqMiniProgramProperties) {
		this.qqMiniProgramProperties = qqMiniProgramProperties;
	}

	/**
	 * 认证信息
	 * @param appid AppID(小程序ID)
	 * @param openid
	 * 用户唯一标识，<a href= "https://q.qq.com/wiki/develop/game/server/open-port/login.html">登录
	 * - code2Session</a>
	 * @param unionid 如果开发者拥有多个移动应用、网站应用、和小程序，可通过 UnionID
	 * 来区分用户的唯一性，因为只要是同一个QQ互联帐号下的移动应用、网站应用和小程序，用户的 UnionID
	 * 是唯一的。换句话说，同一用户，对同一个QQ互联平台下的不同应用，unionid是相同的。详见 <a href=
	 * "https://q.qq.com/wiki/develop/game/frame/open-ability/union-id.html">UnionID
	 * 机制说明</a>。
	 * @param sessionKey 会话密钥
	 * @param details 登录信息
	 * @return 返回 认证信息
	 * @throws OAuth2AuthenticationException OAuth 2.1 可处理的异常，可使用
	 * {@link OAuth2AuthorizationServerConfigurer#tokenEndpoint(Customizer)} 中的
	 * {@link OAuth2TokenEndpointConfigurer#errorResponseHandler(AuthenticationFailureHandler)}
	 * 拦截处理此异常
	 */
	@Override
	public AbstractAuthenticationToken authenticationToken(Authentication clientPrincipal,
			Map<String, Object> additionalParameters, Object details, String appid, String code, String openid,
			Object credentials, String unionid, String sessionKey) throws OAuth2AuthenticationException {
		List<GrantedAuthority> authorities = new ArrayList<>();
		SimpleGrantedAuthority authority = new SimpleGrantedAuthority(qqMiniProgramProperties.getDefaultRole());
		authorities.add(authority);
		User user = new User(openid, sessionKey, authorities);

		UsernamePasswordAuthenticationToken principal = UsernamePasswordAuthenticationToken.authenticated(user, null,
				user.getAuthorities());

		QQMiniProgramAuthenticationToken authenticationToken = new QQMiniProgramAuthenticationToken(authorities,
				clientPrincipal, principal, user, additionalParameters, details, appid, code, openid);

		authenticationToken.setCredentials(credentials);
		authenticationToken.setUnionid(unionid);

		return authenticationToken;
	}

	/**
	 * 根据 AppID(小程序ID)、code、jsCode2SessionUrl 获取Token
	 * @param appid AppID(小程序ID)
	 * @param code <a href=
	 * "https://q.qq.com/wiki/develop/game/server/open-port/login.html">登录-code2Session</a>
	 * @param jsCode2SessionUrl
	 * <a href= "https://q.qq.com/wiki/develop/game/server/open-port/login.html">登录 -
	 * code2Session</a>
	 * @return 返回
	 * <a href= "https://q.qq.com/wiki/develop/game/server/open-port/login.html">登录 -
	 * code2Session</a>
	 * @throws OAuth2AuthenticationException OAuth 2.1 可处理的异常，可使用
	 * {@link OAuth2AuthorizationServerConfigurer#tokenEndpoint(Customizer)} 中的
	 * {@link OAuth2TokenEndpointConfigurer#errorResponseHandler(AuthenticationFailureHandler)}
	 * 拦截处理此异常
	 */
	@Override
	public QQMiniProgramTokenResponse getAccessTokenResponse(String appid, String code, String jsCode2SessionUrl)
			throws OAuth2AuthenticationException {
		Map<String, String> uriVariables = new HashMap<>(8);
		uriVariables.put(OAuth2QQMiniProgramParameterNames.APPID, appid);

		String secret = getSecretByAppid(appid);

		uriVariables.put(OAuth2QQMiniProgramParameterNames.SECRET, secret);
		uriVariables.put(OAuth2QQMiniProgramParameterNames.JS_CODE, code);

		RestTemplate restTemplate = new RestTemplate();

		String forObject = restTemplate.getForObject(jsCode2SessionUrl, String.class, uriVariables);

		QQMiniProgramTokenResponse accessTokenResponse;
		ObjectMapper objectMapper = new ObjectMapper();
		objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
		try {
			accessTokenResponse = objectMapper.readValue(forObject, QQMiniProgramTokenResponse.class);
		}
		catch (JsonProcessingException e) {
			OAuth2Error error = new OAuth2Error(OAuth2QQMiniProgramEndpointUtils.ERROR_CODE,
					"使用QQ小程序授权code：" + code + " 获取Token异常", OAuth2QQMiniProgramEndpointUtils.AUTH_CODE2SESSION_URI);
			throw new OAuth2AuthenticationException(error, e);
		}

		String openid = accessTokenResponse.getOpenid();
		if (openid == null) {
			OAuth2Error error = new OAuth2Error(accessTokenResponse.getErrcode(), accessTokenResponse.getErrmsg(),
					OAuth2QQMiniProgramEndpointUtils.AUTH_CODE2SESSION_URI);
			throw new OAuth2AuthenticationException(error);
		}

		return accessTokenResponse;
	}

	/**
	 * 根据 appid 获取 QQ小程序属性配置
	 * @param appid 小程序ID
	 * @return 返回 QQ小程序属性配置
	 * @throws OAuth2AuthenticationException OAuth 2.1 可处理的异常，可使用
	 * {@link OAuth2AuthorizationServerConfigurer#tokenEndpoint(Customizer)} 中的
	 * {@link OAuth2TokenEndpointConfigurer#errorResponseHandler(AuthenticationFailureHandler)}
	 * 拦截处理此异常
	 */
	@Override
	public QQMiniProgramProperties.QQMiniProgram getQQMiniProgramByAppid(String appid)
			throws OAuth2AuthenticationException {
		List<QQMiniProgramProperties.QQMiniProgram> list = qqMiniProgramProperties.getList();
		if (list == null) {
			OAuth2Error error = new OAuth2Error(OAuth2QQMiniProgramEndpointUtils.ERROR_CODE, "appid 未配置", null);
			throw new AppidQQMiniProgramException(error);
		}

		for (QQMiniProgramProperties.QQMiniProgram qqMiniProgram : list) {
			if (appid.equals(qqMiniProgram.getAppid())) {
				return qqMiniProgram;
			}
		}
		OAuth2Error error = new OAuth2Error(OAuth2QQMiniProgramEndpointUtils.ERROR_CODE, "未匹配到 appid", null);
		throw new AppidQQMiniProgramException(error);
	}

	/**
	 * 根据 AppID(小程序ID) 查询 AppSecret(小程序密钥)
	 * @param appid AppID(小程序ID)
	 * @return 返回 AppSecret(小程序密钥)
	 */
	public String getSecretByAppid(String appid) {
		Assert.notNull(appid, "appid 不能为 null");
		QQMiniProgramProperties.QQMiniProgram qqMiniProgram = getQQMiniProgramByAppid(appid);
		return qqMiniProgram.getSecret();
	}

}
