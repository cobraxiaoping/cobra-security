package com.cobra.validate.code;

import org.springframework.web.context.request.ServletWebRequest;

public interface ValidateCodeGenerator {
     ImageCode createImageCode(ServletWebRequest request);
}
