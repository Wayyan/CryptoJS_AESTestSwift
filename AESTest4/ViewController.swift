//
//  ViewController.swift
//  AESTest4
//
//  Created by Way on 09/05/2024.
//

import UIKit

class ViewController: UIViewController {

    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view.
        
        do {
            print(try EVP_KDF_Util.decrypt( "U2FsdGVkX186d0isM1EnxQL4hFT0CEVPd0YvQuAQDYg=", passwordUtf8: "bLfB9ekEJxaSnYX"))
        } catch let e {
            print("error",e.localizedDescription,e)
        }
    }


}

