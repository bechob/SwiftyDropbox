///
/// Copyright (c) 2016 Dropbox, Inc. All rights reserved.
///

import Foundation
import SafariServices
import UIKit
import WebKit

extension DropboxClientsManager {
    public static func authorizeFromController(_ sharedApplication: UIApplication, controller: UIViewController?, openURL: @escaping ((URL) -> Void)) {
        precondition(DropboxOAuthManager.sharedOAuthManager != nil, "Call `DropboxClientsManager.setupWithAppKey` or `DropboxClientsManager.setupWithTeamAppKey` before calling this method")
        let sharedMobileApplication = MobileSharedApplication(sharedApplication: sharedApplication, controller: controller, openURL: openURL)
        MobileSharedApplication.sharedMobileApplication = sharedMobileApplication
        DropboxOAuthManager.sharedOAuthManager.authorizeFromSharedApplication(sharedMobileApplication)
    }

    public static func setupWithAppKey(_ appKey: String, transportClient: DropboxTransportClient? = nil) {
        setupWithOAuthManager(appKey, oAuthManager: DropboxMobileOAuthManager(appKey: appKey), transportClient: transportClient)
    }

    public static func setupWithAppKeyMultiUser(_ appKey: String, transportClient: DropboxTransportClient? = nil, tokenUid: String?) {
        setupWithOAuthManagerMultiUser(appKey, oAuthManager: DropboxMobileOAuthManager(appKey: appKey), transportClient: transportClient, tokenUid: tokenUid)
    }

    public static func setupWithTeamAppKey(_ appKey: String, transportClient: DropboxTransportClient? = nil) {
        setupWithOAuthManagerTeam(appKey, oAuthManager: DropboxMobileOAuthManager(appKey: appKey), transportClient: transportClient)
    }

    public static func setupWithTeamAppKeyMultiUser(_ appKey: String, transportClient: DropboxTransportClient? = nil, tokenUid: String?) {
        setupWithOAuthManagerMultiUserTeam(appKey, oAuthManager: DropboxMobileOAuthManager(appKey: appKey), transportClient: transportClient, tokenUid: tokenUid)
    }
}

open class DropboxMobileOAuthManager: DropboxOAuthManager {
    var dauthRedirectURL: URL
    
    fileprivate struct AuthUrlParams {
        var state: String
        var codeVerifier: String
        var codeChallenge: String
        var codeChallengeMethod: String
        var tokenAccessType: String
        var scope: String
        
        static func createCodeVerifier() -> String {
            let length = Int.random(in: 43 ... 128)
            let letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.~"
            return String((0...length-1).map{ _ in letters.randomElement()! })
        }
        
        init() {
            codeVerifier = AuthUrlParams.createCodeVerifier()
            codeChallenge = codeVerifier
            codeChallengeMethod = "plain"
            tokenAccessType = "online"
            state = "oauth2code:\(codeVerifier):plain:\(tokenAccessType)"
            scope = "test_scope"
        }
        
        func getExtraAuthQueryParams() -> String {
            return "response_type=code&code_challenge=\(codeChallenge)&code_challenge_method=\(codeChallengeMethod)&token_access_type=\(tokenAccessType)&scope=\(scope)"
        }
    }

    public override init(appKey: String, host: String) {
        self.dauthRedirectURL = URL(string: "db-\(appKey)://1/connect")!
        super.init(appKey: appKey, host:host)
        self.urls.append(self.dauthRedirectURL)
    }
    
    internal override func extractFromUrl(_ url: URL) -> DropboxOAuthResult {
        let result: DropboxOAuthResult
        if url.host == "1" { // dauth
            result = extractfromDAuthURL(url)
        } else {
            result = extractFromRedirectURL(url)
        }
        return result
    }
    
    internal override func checkAndPresentPlatformSpecificAuth(_ sharedApplication: SharedApplication) -> Bool {
        if !self.hasApplicationQueriesSchemes() {
            let message = "DropboxSDK: unable to link; app isn't registered to query for URL schemes dbapi-2 and dbapi-8-emm. Add a dbapi-2 entry and a dbapi-8-emm entry to LSApplicationQueriesSchemes"
            let title = "SwiftyDropbox Error"
            sharedApplication.presentErrorMessage(message, title: title)
            return true
        }
        
        if let scheme = dAuthScheme(sharedApplication) {
            let params = AuthUrlParams()
            UserDefaults.standard.set(params.state, forKey: kDBLinkState)
            UserDefaults.standard.set(params.codeVerifier, forKey: kDBLinkCodeVerifier)
            UserDefaults.standard.synchronize()
            sharedApplication.presentExternalApp(dAuthURL(scheme, authUrlParams: params))
            return true
        }
        return false
    }
    
    open override func handleRedirectURL(_ url: URL) -> DropboxOAuthResult? {
        if let sharedMobileApplication = MobileSharedApplication.sharedMobileApplication {
            sharedMobileApplication.dismissAuthController()
        }
        let result = super.handleRedirectURL(url)
        return result
    }

    fileprivate func dAuthURL(_ scheme: String, authUrlParams: AuthUrlParams?) -> URL {
        var components = URLComponents()
        components.scheme =  scheme
        components.host = "1"
        components.path = "/connect"
        
        if let params = authUrlParams {
            components.queryItems = [
                URLQueryItem(name: "k", value: self.appKey),
                URLQueryItem(name: "s", value: ""),
                URLQueryItem(name: "state", value: params.state),
                URLQueryItem(name: "auth_query_params", value: params.getExtraAuthQueryParams()),
            ]
            print("\(params.getExtraAuthQueryParams())")
        }
        return components.url!
    }
    
    fileprivate func dAuthScheme(_ sharedApplication: SharedApplication) -> String? {
        if sharedApplication.canPresentExternalApp(dAuthURL("dbapi-2", authUrlParams: nil)) {
            return "dbapi-2"
        } else if sharedApplication.canPresentExternalApp(dAuthURL("dbapi-8-emm", authUrlParams: nil)) {
            return "dbapi-8-emm"
        } else {
            return nil
        }
    }
    
    func extractfromDAuthURL(_ url: URL) -> DropboxOAuthResult {
        switch url.path {
        case "/connect":
            var results = [String: String]()
            let pairs  = url.query?.components(separatedBy: "&") ?? []
            
            for pair in pairs {
                let kv = pair.components(separatedBy: "=")
                results.updateValue(kv[1], forKey: kv[0])
            }
            
//            let codeVerifier = UserDefaults.standard.object(forKey: kDBLinkCodeVerifier) as? String
            let state = UserDefaults.standard.object(forKey: kDBLinkState) as? String
            if let state = state {
                let code = results["oauth_token_secret"]!
                let uid = results["uid"]!
                let url = tokenURL(code: code)
               
                let callback: (String?) -> Void = { (accessToken: String?) in
                }
                OAuth2.token(url: url, callback: callback)
                
////                {
                return .success(DropboxAccessToken(accessToken: code, uid: uid))
////                } else {
////                    return .error(.unknown, "Unable to redeem an access token")
////                }
                
            } else {
                return .error(.unknown, "Unable to verify link request")
            }
        default:
            return .error(.accessDenied, "User cancelled Dropbox link")
        }
    }
    
    fileprivate func hasApplicationQueriesSchemes() -> Bool {
        let queriesSchemes = Bundle.main.object(forInfoDictionaryKey: "LSApplicationQueriesSchemes") as? [String] ?? []
        
        var foundApi2 = false
        var foundApi8Emm = false
        for scheme in queriesSchemes {
            if scheme == "dbapi-2" {
                foundApi2 = true
            } else if scheme == "dbapi-8-emm" {
                foundApi8Emm = true
            }
            if foundApi2 && foundApi8Emm {
                return true
            }
        }
        return false
    }
}

open class MobileSharedApplication: SharedApplication {
    public static var sharedMobileApplication: MobileSharedApplication?

    let sharedApplication: UIApplication
    let controller: UIViewController?
    let openURL: ((URL) -> Void)

    public init(sharedApplication: UIApplication, controller: UIViewController?, openURL: @escaping ((URL) -> Void)) {
        // fields saved for app-extension safety
        self.sharedApplication = sharedApplication
        self.controller = controller
        self.openURL = openURL
    }

    open func presentErrorMessage(_ message: String, title: String) {
        let alertController = UIAlertController(
            title: title,
            message: message,
            preferredStyle: UIAlertController.Style.alert)
        if let controller = controller {
            controller.present(alertController, animated: true, completion: { fatalError(message) })
        }
    }

    open func presentErrorMessageWithHandlers(_ message: String, title: String, buttonHandlers: Dictionary<String, () -> Void>) {
        let alertController = UIAlertController(
            title: title,
            message: message,
            preferredStyle: UIAlertController.Style.alert)

        alertController.addAction(UIAlertAction(title: "Cancel", style: .cancel) { (_) in
            if let handler = buttonHandlers["Cancel"] {
                handler()
            }
        })

        alertController.addAction(UIAlertAction(title: "Retry", style: .default) { (_) in
            if let handler = buttonHandlers["Retry"] {
                handler()
            }
        })

        if let controller = controller {
            controller.present(alertController, animated: true, completion: {})
        }
    }

    open func presentPlatformSpecificAuth(_ authURL: URL) -> Bool {
        presentExternalApp(authURL)
        return true
    }

    open func presentAuthChannel(_ authURL: URL, tryIntercept: @escaping ((URL) -> Bool), cancelHandler: @escaping (() -> Void)) {
        if let controller = self.controller {
            let safariViewController = MobileSafariViewController(url: authURL, cancelHandler: cancelHandler)
            controller.present(safariViewController, animated: true, completion: nil)
        }
    }

    open func presentExternalApp(_ url: URL) {
        self.openURL(url)
    }

    open func canPresentExternalApp(_ url: URL) -> Bool {
        return self.sharedApplication.canOpenURL(url)
    }

    open func dismissAuthController() {
        if let controller = self.controller {
            if let presentedViewController = controller.presentedViewController {
                if presentedViewController.isBeingDismissed == false && presentedViewController is MobileSafariViewController {
                    controller.dismiss(animated: true, completion: nil)
                }
            }
        }
    }
}

open class MobileSafariViewController: SFSafariViewController, SFSafariViewControllerDelegate {
    var cancelHandler: (() -> Void) = {}

    public init(url: URL, cancelHandler: @escaping (() -> Void)) {
			  super.init(url: url, entersReaderIfAvailable: false)
        self.cancelHandler = cancelHandler
        self.delegate = self;
    }

    public func safariViewController(_ controller: SFSafariViewController, didCompleteInitialLoad didLoadSuccessfully: Bool) {
        if (!didLoadSuccessfully) {
            controller.dismiss(animated: true, completion: nil)
        }
    }

    public func safariViewControllerDidFinish(_ controller: SFSafariViewController) {
        self.cancelHandler()
    }
    
}

