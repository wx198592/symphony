<#include "macro-head.ftl">
<#include "macro-list.ftl">
<#include "macro-pagination.ftl">
<!DOCTYPE html>
<html>
    <head>
        <@head title="${symphonyLabel} - ${tag.tagTitle}">
        </@head>
        <link type="text/css" rel="stylesheet" href="${staticServePath}/css/index${miniPostfix}.css?${staticResourceVersion}" />
    </head>
    <body>
        <#include "header.ftl">
        <div class="main tag-articles">
            <div class="wrapper">
                <div class="content">
                    <div class="fn-clear title">
                        <#if tag.tagIconPath != "">
                        <div class="avatar fn-left" style="background-image:url('${staticServePath}/images/tags/${tag.tagIconPath}')" alt="${tag.tagTitle}"></div>
                        </#if>
                        <h1 class="fn-inline">
                            <a rel="tag" 
                               title="${tag.tagTitle?url('UTF-8')}" 
                               href="/tags/${tag.tagTitle?url('utf-8')}">${tag.tagTitle}</a>
                        </h1>
                        <#if isLoggedIn>
                        <#if !tag.isReserved || isAdminLoggedIn> &nbsp;
                        <a class="btn small red" href="/post?tags=${tag.tagTitle?url('utf-8')}&type=0">${addArticleLabel}</a>
                        </#if>
                        </#if>
                        <span class='fn-right'>
                            <#if isLoggedIn> &nbsp;
                            <#if isFollowing>
                            <button class="red small" onclick="Util.unfollow(this, '${tag.oId}', 'tag')"> 
                                ${unfollowLabel}
                            </button>
                            <#else>
                            <button class="green small" onclick="Util.follow(this, '${tag.oId}', 'tag')"> 
                                ${followLabel}
                            </button>
                            </#if>
                            </#if>
                            <#if isAdminLoggedIn> &nbsp;
                            <a class="ft-gray icon-setting" href="/admin/tag/${tag.oId}" title="${adminLabel}"></a>
                            </#if>
                        </span>
                    </div>
                    <#if tag.tagIconPath != "">
                    <div class="description">
                        ${tag.tagDescription}
                    </div>
                    </#if>
                <div class="fn-clear">
                    <br/>
                    <ul class="tags">
                        <#list tag.tagRelatedTags as relatedTag>
                        <li>
                            <span>
                                <#if relatedTag.tagIconPath != "">
                                <div style="background-image:url('${staticServePath}/images/tags/${relatedTag.tagIconPath}" alt="${relatedTag.tagTitle}" ></div></#if><a rel="tag" href="/tags/${relatedTag.tagTitle?url('utf-8')}">${relatedTag.tagTitle}</a>
                            </span>
                            <div<#if relatedTag.tagDescription == ''> style="width:auto"</#if>>
                                <div>${relatedTag.tagDescription}</div>
                                <span class="fn-right">
                                    <span class="ft-gray">${referenceLabel}</span> 
                                    ${relatedTag.tagReferenceCount?c} &nbsp;
                                    <span class="ft-gray">${cmtLabel}</span>
                                    ${relatedTag.tagCommentCount?c}&nbsp;
                                </span>
                            </div>
                        </li>
                        </#list>
                    </ul>
                </div>
                <div class="fn-flex">
                    <ul class="status fn-flex fn-flex-1">
                        <li>
                            <strong>${tag.tagReferenceCount?c}</strong>
                            <span class="ft-gray">${referenceLabel}</span>
                        </li>
                        <li>
                            <strong>${tag.tagCommentCount?c}</strong>
                            <span class="ft-gray">${cmtLabel}</span>
                        </li>
                        <li>
                            <strong>${tag.tagFollowerCount?c}</strong>
                            <span class="ft-gray">${followLabel}</span>
                        </li>
                    </ul>
                    <div class="tag-artile-user fn-clear">
                        <a rel="nofollow" class="fn-left" title="${creatorLabel} ${tag.tagCreatorName}" 
                           href="/member/${tag.tagCreatorName}">
                            <div class="avatar" style="background-image:url('${tag.tagCreatorThumbnailURL}-64.jpg?${tag.tagCreatorThumbnailUpdateTime?c}')"></div>
                        </a>
                        <div class="fn-right">
                            <#list tag.tagParticipants as commenter>
                            <#if commenter_index < 4>
                            <a rel="nofollow" class="fn-left" 
                               title="${contributorLabel} ${commenter.tagParticipantName}"
                               href="/member/${commenter.tagParticipantName}">
                                <div class="avatar" style="background-image:url('${commenter.tagParticipantThumbnailURL}-64.jpg?${commenter.tagParticipantThumbnailUpdateTime?c}')"></div>
                            </a>
                            </#if>
                            </#list>
                        </div>
                    </div>
                </div>
                <div class="fn-clear">
                    <@list listData=articles/>
                    <@pagination url="/tags/${tag.tagTitle?url('utf-8')}"/>
                </div>
            </div> 
            <div class="side">
                <#include "side.ftl">
            </div>
        </div>
    </div>
    <#include "footer.ftl">
    <script>
        Util.initArticlePreview();
    </script>
</body>
</html>
