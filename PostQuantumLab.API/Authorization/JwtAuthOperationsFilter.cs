using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.OpenApi.Models;
using Swashbuckle.AspNetCore.SwaggerGen;
using System.Reflection;

namespace PostQuantumLab.API.Authorization
{
    public class JwtAuthOperationsFilter : IOperationFilter
    {
        public void Apply(OpenApiOperation operation, OperationFilterContext ctx)
        {
            if (ctx.ApiDescription.ActionDescriptor is ControllerActionDescriptor descriptor)
            {
                // If not [AllowAnonymous] and [Authorize] on either the endpoint or the controller...
                if (!ctx.ApiDescription.CustomAttributes().Any((a) => a is AllowAnonymousAttribute)
                    && (ctx.ApiDescription.CustomAttributes().Any((a) => a is AuthorizeAttribute)
                        || descriptor.ControllerTypeInfo.GetCustomAttribute<AuthorizeAttribute>() != null))
                {
                    operation.Security.Add(new OpenApiSecurityRequirement
                    {
                        [new OpenApiSecurityScheme
                        {
                            Reference = new OpenApiReference
                            {
                                Type = ReferenceType.SecurityScheme,
                                Id = "Bearer"
                            },
                            Scheme = "Bearer",
                            Name = "Bearer",
                            In = ParameterLocation.Header,
                        }] = Array.Empty<string>()
                    });
                }
            }
        }
    }
}
