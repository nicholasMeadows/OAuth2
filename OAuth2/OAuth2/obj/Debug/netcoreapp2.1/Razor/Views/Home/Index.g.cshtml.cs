#pragma checksum "C:\Users\nicholas.meadows\Documents\GitHub\OAuth2\OAuth2\OAuth2\Views\Home\Index.cshtml" "{ff1816ec-aa5e-4d10-87f7-6f4963833460}" "34e9a27459d17b05237472930614da08b3da38af"
// <auto-generated/>
#pragma warning disable 1591
[assembly: global::Microsoft.AspNetCore.Razor.Hosting.RazorCompiledItemAttribute(typeof(AspNetCore.Views_Home_Index), @"mvc.1.0.view", @"/Views/Home/Index.cshtml")]
[assembly:global::Microsoft.AspNetCore.Mvc.Razor.Compilation.RazorViewAttribute(@"/Views/Home/Index.cshtml", typeof(AspNetCore.Views_Home_Index))]
namespace AspNetCore
{
    #line hidden
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.AspNetCore.Mvc.Rendering;
    using Microsoft.AspNetCore.Mvc.ViewFeatures;
    [global::Microsoft.AspNetCore.Razor.Hosting.RazorSourceChecksumAttribute(@"SHA1", @"34e9a27459d17b05237472930614da08b3da38af", @"/Views/Home/Index.cshtml")]
    public class Views_Home_Index : global::Microsoft.AspNetCore.Mvc.Razor.RazorPage<OAuth2.Models.UserPassModel>
    {
        #pragma warning disable 1998
        public async override global::System.Threading.Tasks.Task ExecuteAsync()
        {
#line 1 "C:\Users\nicholas.meadows\Documents\GitHub\OAuth2\OAuth2\OAuth2\Views\Home\Index.cshtml"
  
    ViewData["Title"] = "Home Page";

#line default
#line hidden
            BeginContext(45, 2, true);
            WriteLiteral("\r\n");
            EndContext();
            BeginContext(83, 2, true);
            WriteLiteral("\r\n");
            EndContext();
#line 7 "C:\Users\nicholas.meadows\Documents\GitHub\OAuth2\OAuth2\OAuth2\Views\Home\Index.cshtml"
 using (Html.BeginForm("Login", "Home", FormMethod.Post))
{
    

#line default
#line hidden
#line 9 "C:\Users\nicholas.meadows\Documents\GitHub\OAuth2\OAuth2\OAuth2\Views\Home\Index.cshtml"
     if (@Model == null)
    {
        
        

#line default
#line hidden
#line 12 "C:\Users\nicholas.meadows\Documents\GitHub\OAuth2\OAuth2\OAuth2\Views\Home\Index.cshtml"
         if (TempData["err"] != null)
        {

#line default
#line hidden
            BeginContext(240, 68, true);
            WriteLiteral("            <p style=\"color:red\">Invalid username or password!</p>\r\n");
            EndContext();
#line 15 "C:\Users\nicholas.meadows\Documents\GitHub\OAuth2\OAuth2\OAuth2\Views\Home\Index.cshtml"
        }

#line default
#line hidden
            BeginContext(319, 21, true);
            WriteLiteral("        <a>Username: ");
            EndContext();
            BeginContext(341, 31, false);
#line 16 "C:\Users\nicholas.meadows\Documents\GitHub\OAuth2\OAuth2\OAuth2\Views\Home\Index.cshtml"
                Write(Html.EditorFor(m => m.username));

#line default
#line hidden
            EndContext();
            BeginContext(372, 43, true);
            WriteLiteral("</a><a style=\"color:red; font-weight:bold\">");
            EndContext();
            BeginContext(416, 42, false);
#line 16 "C:\Users\nicholas.meadows\Documents\GitHub\OAuth2\OAuth2\OAuth2\Views\Home\Index.cshtml"
                                                                                           Write(Html.ValidationMessageFor(m => m.username));

#line default
#line hidden
            EndContext();
            BeginContext(458, 43, true);
            WriteLiteral("</a>\r\n        <br />\r\n        <a>Password: ");
            EndContext();
            BeginContext(502, 33, false);
#line 18 "C:\Users\nicholas.meadows\Documents\GitHub\OAuth2\OAuth2\OAuth2\Views\Home\Index.cshtml"
                Write(Html.PasswordFor(m => m.password));

#line default
#line hidden
            EndContext();
            BeginContext(535, 43, true);
            WriteLiteral("</a><a style=\"color:red; font-weight:bold\">");
            EndContext();
            BeginContext(579, 42, false);
#line 18 "C:\Users\nicholas.meadows\Documents\GitHub\OAuth2\OAuth2\OAuth2\Views\Home\Index.cshtml"
                                                                                             Write(Html.ValidationMessageFor(m => m.password));

#line default
#line hidden
            EndContext();
            BeginContext(621, 69, true);
            WriteLiteral("</a>\r\n        <br />\r\n        <input type=\"submit\" value=\"Login\" />\r\n");
            EndContext();
#line 21 "C:\Users\nicholas.meadows\Documents\GitHub\OAuth2\OAuth2\OAuth2\Views\Home\Index.cshtml"

    }

#line default
#line hidden
#line 22 "C:\Users\nicholas.meadows\Documents\GitHub\OAuth2\OAuth2\OAuth2\Views\Home\Index.cshtml"
     
}

#line default
#line hidden
            BeginContext(702, 317, true);
            WriteLiteral(@"
<script src=""https://ajax.aspnetcdn.com/ajax/jQuery/jquery-2.2.0.min.js""></script>

<script src=""https://ajax.aspnetcdn.com/ajax/jquery.validate/1.16.0/jquery.validate.min.js""></script>
<script src=""https://ajax.aspnetcdn.com/ajax/jquery.validation.unobtrusive/3.2.6/jquery.validate.unobtrusive.min.js""></script>");
            EndContext();
        }
        #pragma warning restore 1998
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.ViewFeatures.IModelExpressionProvider ModelExpressionProvider { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.IUrlHelper Url { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.IViewComponentHelper Component { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.Rendering.IJsonHelper Json { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.Rendering.IHtmlHelper<OAuth2.Models.UserPassModel> Html { get; private set; }
    }
}
#pragma warning restore 1591
