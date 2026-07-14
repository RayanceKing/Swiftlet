//
//  tunnel.swift
//  tunnel
//
//  Created by 王宇亮 on 7/14/26.
//

import AppIntents

struct tunnel: AppIntent {
    static var title: LocalizedStringResource { "tunnel" }
    
    func perform() async throws -> some IntentResult {
        return .result()
    }
}
