# spring-security-basic

## 1. Spring Security Architecture
   
(https://docs.spring.io/spring-security/reference/servlet/architecture.html)

<img width="500" alt="image" src="https://user-images.githubusercontent.com/48561660/195978180-30fd6734-131d-495f-b6d9-6270bb121e19.png">

1. 스프링 시큐리티는 서블릿 필터 기반하여 동작한다. 


- **DelegatingFilterProxy** : Filter 인터페이스를 구현하는 Spring 관리 빈에 위임하는 표준 서블릿 필터용 프록시.
- **FilterChainProxy** : SecurityFilterChain 을 통해 많은 `Filter` 인스턴스들이 역할을 위임하는 필터.
- **SecurityFilterChain** : 요청에 따라 `Security Filter` 를 호출을 결정하는데 사용된다.   
- **SecurityFilter** : `SecurityFilterChain` 에 소속된 필터이다. `SecuityFilter` 는 빈으로 등록된다. (DelegatingFilterProxy 아님) 
  - SecurityFilterChain 으로 등록하면 빈으로 관리되기 때문에 디버깅하기 쉽다.
  <details>
  <summary>Security Filter 순서</summary>

  - ForceEagerSessionCreationFilter
  - ChannelProcessingFilter
  - WebAsyncManagerIntegrationFilter
  - SecurityContextPersistenceFilter
  - HeaderWriterFilter
  - CorsFilter
  - CsrfFilter
  - LogoutFilter
  - OAuth2AuthorizationRequestRedirectFilter
  - Saml2WebSsoAuthenticationRequestFilter
  - X509AuthenticationFilter
  - AbstractPreAuthenticatedProcessingFilter
  - CasAuthenticationFilter
  - OAuth2LoginAuthenticationFilter
  - Saml2WebSsoAuthenticationFilter
  - `UsernamePasswordAuthenticationFilter`
  - OpenIDAuthenticationFilter
  - DefaultLoginPageGeneratingFilter
  - DefaultLogoutPageGeneratingFilter
  - ConcurrentSessionFilter
  - DigestAuthenticationFilter
  - BearerTokenAuthenticationFilter
  - `BasicAuthenticationFilter`
  - RequestCacheAwareFilter
  - SecurityContextHolderAwareRequestFilter
  - JaasApiIntegrationFilter
  - RememberMeAuthenticationFilter
  - AnonymousAuthenticationFilter
  - OAuth2AuthorizationCodeGrantFilter
  - SessionManagementFilter
  - `ExceptionTranslationFilter`
  - `FilterSecurityInterceptor
  - SwitchUserFilter
    </details>

<br>

## 2. DelegatingFilterProxy

```java
public class DelegatingFilterProxy extends GenericFilterBean {

  @Nullable
  private String contextAttribute;

  @Nullable
  private WebApplicationContext webApplicationContext;

  @Nullable
  private String targetBeanName;

  private boolean targetFilterLifecycle = false;

  @Nullable
  private volatile Filter delegate;

  @Override
  public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain)
          throws ServletException, IOException {

    // Lazily initialize the delegate if necessary.
    Filter delegateToUse = this.delegate;
    if (delegateToUse == null) {
      synchronized (this.delegateMonitor) {
        delegateToUse = this.delegate;
        if (delegateToUse == null) {
          WebApplicationContext wac = findWebApplicationContext();
          if (wac == null) {
            throw new IllegalStateException("No WebApplicationContext found: " +
                    "no ContextLoaderListener or DispatcherServlet registered?");
          }
          delegateToUse = initDelegate(wac);
        }
        this.delegate = delegateToUse;
      }
    }

    // Let the delegate perform the actual doFilter operation.
    invokeDelegate(delegateToUse, request, response, filterChain);
  }

  protected void invokeDelegate(Filter delegate, ServletRequest request, ServletResponse response, FilterChain filterChain)
          throws ServletException, IOException {

    delegate.doFilter(request, response, filterChain);
  }
  
}
```
- Filter 인터페이스를 구현하는 Spring 관리 빈에 위임하는 표준 서블릿 필터용 프록시. Spring의 루트 애플리케이션 컨텍스트에 있는 빈 이름에 해당하는 지정된 필터 이름과 함께 DelegatingFilterProxy 정의를 포함한다. 필터 프록시에 대한
  모든 호출은 표준 서블릿 필터 인터페이스를 구현하는 데 필요한 Spring 컨텍스트의 해당 빈에 위임한다.
- 즉, 표준 서블릿 컨테이너와 Spring IOC 컨테이너의 다리 역할한다. `DelegatingFilterProxy` 는 서블릿 필터이며, Spring IOC 컨테이가 관리는 `Filter 
  Bean` 을 갖고 있고 이 Filter Bean은 FilterChainProxy 이며 이 객체 안에서 Security와 관련된 로직을 한다.
- `DelegatingFilterProxy` 는 스프링부트 기준으로 `SecurityFilterAutoConfiguration` 에서 설정된다.  

## 3. FilterChainProxy

### (1) 공식 문서 내용

> Spring Security’s Servlet support is contained within FilterChainProxy. 
> FilterChainProxy is a special Filter provided by Spring Security that allows delegating to many Filter instances
> through SecurityFilterChain. Since FilterChainProxy is a Bean, it is typically wrapped in a DelegatingFilterProxy.

- Spring Security 의 Servlet 지원은 FilterChainProxy 에 포함되어 있습니다. FilterChainProxy 는 Spring Security 에서 제공하는 특수 필터로
SecurityFilterChain 을 통해 많은 Filter 인스턴스에 위임 할 수 있다. FilterChainProxy 는 Bean 이므로 일반적으로 DelegatingFilterProxy
로 래핑된다.

- FilterChainProxy 를 사용했을 때 장점은 Spring Security 의 모든 Servlet 지원을 위한 시작점을 제공한다.(RequestMatcher 인터페이스를 사용해
  어떤 SecurityFilterChain 을 사용해야 하는지 결정한다.) 또한, Spring Security 의 HttpFirewall 을 적용하여 특정 유형의 공격으로부터 애플리케이션을 보호한다.

<br>

### (2) 자바 코드

```java
public class FilterChainProxy extends GenericFilterBean {

  private List<SecurityFilterChain> filterChains;

  @Override
  public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
          throws IOException, ServletException {
    boolean clearContext = request.getAttribute(FILTER_APPLIED) == null;
    if (!clearContext) {
      doFilterInternal(request, response, chain);
      return;
    }
    try {
      request.setAttribute(FILTER_APPLIED, Boolean.TRUE);
      doFilterInternal(request, response, chain);
    } catch (Exception ex) {
      Throwable[] causeChain = this.throwableAnalyzer.determineCauseChain(ex);
      Throwable requestRejectedException = this.throwableAnalyzer
              .getFirstThrowableOfType(RequestRejectedException.class, causeChain);
      if (!(requestRejectedException instanceof RequestRejectedException)) {
        throw ex;
      }
      this.requestRejectedHandler.handle((HttpServletRequest) request, (HttpServletResponse) response,
              (RequestRejectedException) requestRejectedException);
    } finally {
      SecurityContextHolder.clearContext();
      request.removeAttribute(FILTER_APPLIED);
    }
  }

  private void doFilterInternal(ServletRequest request, ServletResponse response, FilterChain chain)
          throws IOException, ServletException {
    FirewalledRequest firewallRequest = this.firewall.getFirewalledRequest((HttpServletRequest) request);
    HttpServletResponse firewallResponse = this.firewall.getFirewalledResponse((HttpServletResponse) response);
    List<Filter> filters = getFilters(firewallRequest);
    if (filters == null || filters.size() == 0) {
      if (logger.isTraceEnabled()) {
        logger.trace(LogMessage.of(() -> "No security for " + requestLine(firewallRequest)));
      }
      firewallRequest.reset();
      chain.doFilter(firewallRequest, firewallResponse);
      return;
    }
    if (logger.isDebugEnabled()) {
      logger.debug(LogMessage.of(() -> "Securing " + requestLine(firewallRequest)));
    }
    VirtualFilterChain virtualFilterChain = new VirtualFilterChain(firewallRequest, chain, filters);
    virtualFilterChain.doFilter(firewallRequest, firewallResponse);
  }
}

```

## 4. SecurityFilterChain

### (1) 공식 문서 내용

> Defines a filter chain which is capable of being matched against an HttpServletRequest. 
> in order to decide whether it applies to that request.

- 해당 요청에 적용되는지 여부를 결정하기 위해 HttpServletRequest 와 일치시킬 수 있는 필터 체인을 정의한다.

<br>

### (2) 그림 예시

![image](https://user-images.githubusercontent.com/48561660/195984202-e47bb2fd-afc7-46a3-88e2-d4723d88c5a5.png)

- 다중 SecurityFilterChain 일 경우, 일치하는 첫 번째 SecurityFilterChain 만 호출된다. (e.g. /api/messages/의 URL 이 요청되면 먼저
  SecurityFilterChain0의 /api/** 패턴과 일치하므로 SecurityFilterChain0에서도 일치하더라도 SecurityFilterChain0만 호출된다.)

<br>

### (3) 자바 코드

```java
public final class DefaultSecurityFilterChain implements SecurityFilterChain {

	private static final Log logger = LogFactory.getLog(DefaultSecurityFilterChain.class);

	private final RequestMatcher requestMatcher;

	private final List<Filter> filters;

	public DefaultSecurityFilterChain(RequestMatcher requestMatcher, Filter... filters) {
		this(requestMatcher, Arrays.asList(filters));
	}

	public DefaultSecurityFilterChain(RequestMatcher requestMatcher, List<Filter> filters) {
		if (filters.isEmpty()) {
			logger.info(LogMessage.format("Will not secure %s", requestMatcher));
		}
		else {
			logger.info(LogMessage.format("Will secure %s with %s", requestMatcher, filters));
		}
		this.requestMatcher = requestMatcher;
		this.filters = new ArrayList<>(filters);
	}

	public RequestMatcher getRequestMatcher() {
		return this.requestMatcher;
	}

	@Override
	public List<Filter> getFilters() {
		return this.filters;
	}

	@Override
	public boolean matches(HttpServletRequest request) {
		return this.requestMatcher.matches(request);
	}

}
```

- 해당 요청의 특정 URL 과 매칭될 경우, SecurityFilterChain 이 실행되도록 구현되어 있다.
- 위에서 언급한 URL 우선 일치하는 SecurityFilterChain 이 호출된다. 관련된 코드는 
  `WebSecurity.performBuild()` 메서드 에서 처리된다.

- **WebSecurity.performBuild() 메서드**
  ```java
  package org.springframework.security.config.annotation.web.builders;
  
  public final class WebSecurity extends AbstractConfiguredSecurityBuilder<Filter, WebSecurity>
          implements SecurityBuilder<Filter>, ApplicationContextAware, ServletContextAware {
      
    ...
  
    @Override
    protected Filter performBuild() throws Exception {
      ...
      int chainSize = this.ignoredRequests.size() + this.securityFilterChainBuilders.size();
      List<SecurityFilterChain> securityFilterChains = new ArrayList<>(chainSize);
      List<RequestMatcherEntry<List<WebInvocationPrivilegeEvaluator>>> requestMatcherPrivilegeEvaluatorsEntries = new ArrayList<>();
      for (RequestMatcher ignoredRequest : this.ignoredRequests) {
        WebSecurity.this.logger.warn("You are asking Spring Security to ignore " + ignoredRequest
                + ". This is not recommended -- please use permitAll via HttpSecurity#authorizeHttpRequests instead.");
        SecurityFilterChain securityFilterChain = new DefaultSecurityFilterChain(ignoredRequest);
        securityFilterChains.add(securityFilterChain);
        requestMatcherPrivilegeEvaluatorsEntries
                .add(getRequestMatcherPrivilegeEvaluatorsEntry(securityFilterChain)); // 이 부분
      }
      for (SecurityBuilder<? extends SecurityFilterChain> securityFilterChainBuilder : this.securityFilterChainBuilders) {
        SecurityFilterChain securityFilterChain = securityFilterChainBuilder.build();
        securityFilterChains.add(securityFilterChain);
        requestMatcherPrivilegeEvaluatorsEntries
                .add(getRequestMatcherPrivilegeEvaluatorsEntry(securityFilterChain)); // 이 부분
      }
      ...
    }
  }
  ```

<br>
